// Package snowflake is the advisor for snowflake database.
package snowflake

import (
	"fmt"
	"strconv"

	"github.com/antlr4-go/antlr/v4"
	parser "github.com/bytebase/snowsql-parser"
	"github.com/pkg/errors"

	"github.com/bytebase/bytebase/backend/plugin/advisor"
	storepb "github.com/bytebase/bytebase/proto/generated-go/store"
)

const (
	// varcharDefaultLength is the default length of varchar in Snowflake.
	// https://docs.snowflake.com/en/sql-reference/data-types-text
	varcharDefaultLength = 16_777_216
)

var (
	_ advisor.Advisor = (*ColumnMaximumVarcharLengthAdvisor)(nil)
)

func init() {
	advisor.Register(storepb.Engine_SNOWFLAKE, advisor.SnowflakeColumnMaximumVarcharLength, &ColumnMaximumVarcharLengthAdvisor{})
}

// ColumnMaximumVarcharLengthAdvisor is the advisor checking for maximum varchar length.
type ColumnMaximumVarcharLengthAdvisor struct {
}

// Check checks for maximum varchar length.
func (*ColumnMaximumVarcharLengthAdvisor) Check(ctx advisor.Context, _ string) ([]advisor.Advice, error) {
	tree, ok := ctx.AST.(antlr.Tree)
	if !ok {
		return nil, errors.Errorf("failed to convert to Tree")
	}

	level, err := advisor.NewStatusBySQLReviewRuleLevel(ctx.Rule.Level)
	if err != nil {
		return nil, err
	}
	payload, err := advisor.UnmarshalNumberTypeRulePayload(ctx.Rule.Payload)
	if err != nil {
		return nil, err
	}

	listener := &columnMaximumVarcharLengthChecker{
		level:   level,
		title:   string(ctx.Rule.Type),
		maximum: payload.Number,
	}

	if listener.maximum > 0 {
		antlr.ParseTreeWalkerDefault.Walk(listener, tree)
	}

	return listener.generateAdvice()
}

// columnMaximumVarcharLengthChecker is the listener for maximum varchar length.
type columnMaximumVarcharLengthChecker struct {
	*parser.BaseSnowflakeParserListener

	level   advisor.Status
	title   string
	maximum int

	adviceList []advisor.Advice
}

// generateAdvice returns the advices generated by the listener, the advices must not be empty.
func (l *columnMaximumVarcharLengthChecker) generateAdvice() ([]advisor.Advice, error) {
	if len(l.adviceList) == 0 {
		l.adviceList = append(l.adviceList, advisor.Advice{
			Status:  advisor.Success,
			Code:    advisor.Ok,
			Title:   "OK",
			Content: "",
		})
	}
	return l.adviceList, nil
}

// EnterData_type is called when production data_type is entered.
func (l *columnMaximumVarcharLengthChecker) EnterData_type(ctx *parser.Data_typeContext) {
	if ctx.VARCHAR() == nil {
		return
	}

	length := varcharDefaultLength
	if v := ctx.Num(0); v != nil {
		var err error
		length, err = strconv.Atoi(v.GetText())
		if err != nil {
			return
		}
	}

	if length > l.maximum {
		l.adviceList = append(l.adviceList, advisor.Advice{
			Status:  l.level,
			Code:    advisor.VarcharLengthExceedsLimit,
			Title:   l.title,
			Content: fmt.Sprintf("The maximum varchar length is %d.", l.maximum),
			Line:    ctx.GetStart().GetLine(),
		})
	}
}
