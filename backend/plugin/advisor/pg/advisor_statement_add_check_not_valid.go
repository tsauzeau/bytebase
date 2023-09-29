package pg

// Framework code is generated by the generator.

import (
	"github.com/pkg/errors"

	"github.com/bytebase/bytebase/backend/plugin/advisor"
	"github.com/bytebase/bytebase/backend/plugin/parser/sql/ast"
	storepb "github.com/bytebase/bytebase/proto/generated-go/store"
)

var (
	_ advisor.Advisor = (*StatementAddCheckNotValidAdvisor)(nil)
	_ ast.Visitor     = (*statementAddCheckNotValidChecker)(nil)
)

func init() {
	advisor.Register(storepb.Engine_POSTGRES, advisor.PostgreSQLAddCheckNotValid, &StatementAddCheckNotValidAdvisor{})
}

// StatementAddCheckNotValidAdvisor is the advisor checking for to add check not valid.
type StatementAddCheckNotValidAdvisor struct {
}

// Check checks for to add check not valid.
func (*StatementAddCheckNotValidAdvisor) Check(ctx advisor.Context, _ string) ([]advisor.Advice, error) {
	stmtList, ok := ctx.AST.([]ast.Node)
	if !ok {
		return nil, errors.Errorf("failed to convert to Node")
	}

	level, err := advisor.NewStatusBySQLReviewRuleLevel(ctx.Rule.Level)
	if err != nil {
		return nil, err
	}
	checker := &statementAddCheckNotValidChecker{
		level: level,
		title: string(ctx.Rule.Type),
	}

	for _, stmt := range stmtList {
		checker.line = stmt.LastLine()
		ast.Walk(checker, stmt)
	}

	if len(checker.adviceList) == 0 {
		checker.adviceList = append(checker.adviceList, advisor.Advice{
			Status:  advisor.Success,
			Code:    advisor.Ok,
			Title:   "OK",
			Content: "",
		})
	}
	return checker.adviceList, nil
}

type statementAddCheckNotValidChecker struct {
	adviceList []advisor.Advice
	level      advisor.Status
	title      string
	line       int
}

// Visit implements ast.Visitor interface.
func (checker *statementAddCheckNotValidChecker) Visit(in ast.Node) ast.Visitor {
	if node, ok := in.(*ast.AddConstraintStmt); ok {
		if node.Constraint.Type == ast.ConstraintTypeCheck && !node.Constraint.SkipValidation {
			checker.adviceList = append(checker.adviceList, advisor.Advice{
				Status:  checker.level,
				Code:    advisor.StatementAddCheckWithValidation,
				Title:   checker.title,
				Content: "Adding check constraints with validation will block reads and writes. You can add check constraints not valid and then validate separately",
				Line:    checker.line,
			})
		}
	}

	return checker
}
