package v1

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pkg/errors"

	"github.com/bytebase/bytebase/backend/common"
	api "github.com/bytebase/bytebase/backend/legacyapi"
	"github.com/bytebase/bytebase/backend/store"
	storepb "github.com/bytebase/bytebase/proto/generated-go/store"
	v1pb "github.com/bytebase/bytebase/proto/generated-go/v1"
)

// ReviewService implements the review service.
type ReviewService struct {
	v1pb.UnimplementedReviewServiceServer
	store *store.Store
}

// NewReviewService creates a new ReviewService.
func NewReviewService(store *store.Store) *ReviewService {
	return &ReviewService{
		store: store,
	}
}

// GetReview gets a review.
// Currently, only review.ApprovalTemplates and review.Approvers are set.
func (s *ReviewService) GetReview(ctx context.Context, request *v1pb.GetReviewRequest) (*v1pb.Review, error) {
	reviewID, err := getReviewID(request.Name)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	issue, err := s.store.GetIssueV2(ctx, &store.FindIssueMessage{UID: &reviewID})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get issue, error: %v", err)
	}
	review, err := convertToReview(ctx, s.store, issue)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert to review, error: %v", err)
	}
	return review, nil
}

// ApproveReview approves the approval flow of the review.
func (s *ReviewService) ApproveReview(ctx context.Context, request *v1pb.ApproveReviewRequest) (*v1pb.Review, error) {
	reviewID, err := getReviewID(request.Name)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	issue, err := s.store.GetIssueV2(ctx, &store.FindIssueMessage{UID: &reviewID})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get issue, error: %v", err)
	}
	payload := &storepb.IssuePayload{}
	if err := protojson.Unmarshal([]byte(issue.Payload), payload); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmarshal issue payload, error: %v", err)
	}
	if payload.Approval == nil {
		return nil, status.Errorf(codes.Internal, "issue payload approval is nil")
	}
	if !payload.Approval.ApprovalFindingDone {
		return nil, status.Errorf(codes.FailedPrecondition, "approval template finding is not done")
	}
	if len(payload.Approval.ApprovalTemplates) != 0 {
		return nil, status.Errorf(codes.Internal, "expecting one approval template but got %v", len(payload.Approval.ApprovalTemplates))
	}

	step := findPendingStep(payload.Approval.ApprovalTemplates[0], payload.Approval.Approvers)
	if step == nil {
		return nil, status.Errorf(codes.InvalidArgument, "the review has been approved")
	}

	principalID := ctx.Value(common.PrincipalIDContextKey).(int)
	user, err := s.store.GetUserByID(ctx, principalID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to find user by id %v", principalID)
	}

	policy, err := s.store.GetProjectPolicy(ctx, &store.GetProjectPolicyMessage{UID: &issue.Project.UID})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get project policy, error: %v", err)
	}

	canApprove, err := canUserApproveStep(step, user, policy)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check if principal can approve step, error: %v", err)
	}
	if !canApprove {
		return nil, status.Errorf(codes.PermissionDenied, "cannot approve because the user does not have the required permission")
	}
	payload.Approval.Approvers = append(payload.Approval.Approvers, &storepb.IssuePayloadApproval_Approver{
		Status:      storepb.IssuePayloadApproval_Approver_APPROVED,
		PrincipalId: int32(principalID),
	})
	payloadBytes, err := protojson.Marshal(payload)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal issue payload, error: %v", err)
	}
	payloadStr := string(payloadBytes)

	issue, err = s.store.UpdateIssueV2(ctx, issue.UID, &store.UpdateIssueMessage{
		Payload: &payloadStr,
	}, api.SystemBotID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update issue, error: %v", err)
	}

	review, err := convertToReview(ctx, s.store, issue)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert to review, error: %v", err)
	}
	return review, nil
}

func findPendingStep(template *storepb.ApprovalTemplate, approvers []*storepb.IssuePayloadApproval_Approver) *storepb.ApprovalStep {
	// We can do the finding like this for now because we are presuming that
	// one step is approved by one approver.
	if len(approvers) >= len(template.Flow.Steps) {
		return nil
	}
	return template.Flow.Steps[len(approvers)]
}

func canUserApproveStep(step *storepb.ApprovalStep, user *store.UserMessage, policy *store.IAMPolicyMessage) (bool, error) {
	if len(step.Nodes) != 1 {
		return false, errors.Errorf("expecting one node but got %v", len(step.Nodes))
	}
	if step.Type != storepb.ApprovalStep_ANY {
		return false, errors.Errorf("expecting ANY step type but got %v", step.Type)
	}
	node := step.Nodes[0]
	if node.Type != storepb.ApprovalNode_ANY_IN_GROUP {
		return false, errors.Errorf("expecting ANY_IN_GROUP node type but got %v", node.Type)
	}
	groupValue, ok := node.Payload.(*storepb.ApprovalNode_GroupValue_)
	if !ok {
		return false, errors.Errorf("expecting GroupValue payload but got %T", node.Payload)
	}
	userHasRole := map[storepb.ApprovalNode_GroupValue]bool{
		convertWorkspaceRoleToApprovalNodeGroupValue(user.Role): true,
	}
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if member.ID == user.ID {
				userHasRole[convertProjectRoleToApprovalNodeGroupValue(binding.Role)] = true
				break
			}
		}
	}
	if userHasRole[groupValue.GroupValue] {
		return true, nil
	}

	return false, nil
}

func convertToReview(ctx context.Context, store *store.Store, issue *store.IssueMessage) (*v1pb.Review, error) {
	issuePayload := &storepb.IssuePayload{}
	if err := protojson.Unmarshal([]byte(issue.Payload), issuePayload); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal issue payload")
	}

	review := &v1pb.Review{}
	if issuePayload.Approval != nil {
		review.ApprovalFindingDone = issuePayload.Approval.ApprovalFindingDone
		for _, template := range issuePayload.Approval.ApprovalTemplates {
			review.ApprovalTemplates = append(review.ApprovalTemplates, convertToApprovalTemplate(template))
		}
		for _, approver := range issuePayload.Approval.Approvers {
			convertedApprover := &v1pb.Review_Approver{Status: v1pb.Review_Approver_Status(approver.Status)}
			user, err := store.GetUserByID(ctx, int(approver.PrincipalId))
			if err != nil {
				return nil, errors.Wrapf(err, "failed to find user by id %v", approver.PrincipalId)
			}
			convertedApprover.Principal = fmt.Sprintf("user:%s", user.Email)

			review.Approvers = append(review.Approvers, convertedApprover)
		}
	}

	return review, nil
}

func convertToApprovalTemplate(template *storepb.ApprovalTemplate) *v1pb.ApprovalTemplate {
	return &v1pb.ApprovalTemplate{
		Flow:        convertToApprovalFlow(template.Flow),
		Title:       template.Title,
		Description: template.Description,
	}
}

func convertToApprovalFlow(flow *storepb.ApprovalFlow) *v1pb.ApprovalFlow {
	convertedFlow := &v1pb.ApprovalFlow{}
	for _, step := range flow.Steps {
		convertedFlow.Steps = append(convertedFlow.Steps, convertToApprovalStep(step))
	}
	return convertedFlow
}

func convertToApprovalStep(step *storepb.ApprovalStep) *v1pb.ApprovalStep {
	convertedStep := &v1pb.ApprovalStep{
		Type: v1pb.ApprovalStep_Type(step.Type),
	}
	for _, node := range step.Nodes {
		convertedStep.Nodes = append(convertedStep.Nodes, convertToApprovalNode(node))
	}
	return convertedStep
}

func convertToApprovalNode(node *storepb.ApprovalNode) *v1pb.ApprovalNode {
	if v, ok := node.Payload.(*storepb.ApprovalNode_GroupValue_); ok {
		return &v1pb.ApprovalNode{
			Type: v1pb.ApprovalNode_ANY_IN_GROUP,
			Payload: &v1pb.ApprovalNode_GroupValue_{
				GroupValue: v1pb.ApprovalNode_GroupValue(v.GroupValue),
			},
		}
	}
	return &v1pb.ApprovalNode{}
}

func convertWorkspaceRoleToApprovalNodeGroupValue(role api.Role) storepb.ApprovalNode_GroupValue {
	switch role {
	case api.DBA:
		return storepb.ApprovalNode_WORKSPACE_DBA
	case api.Owner:
		return storepb.ApprovalNode_WORKSPACE_OWNER
	default:
		return storepb.ApprovalNode_GROUP_VALUE_UNSPECIFILED
	}
}

func convertProjectRoleToApprovalNodeGroupValue(role api.Role) storepb.ApprovalNode_GroupValue {
	switch role {
	case api.Owner:
		return storepb.ApprovalNode_PROJECT_OWNER
	case api.Developer:
		return storepb.ApprovalNode_PROJECT_MEMBER
	default:
		return storepb.ApprovalNode_GROUP_VALUE_UNSPECIFILED
	}
}