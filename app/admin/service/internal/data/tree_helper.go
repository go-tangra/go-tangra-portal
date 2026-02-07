package data

import (
	"context"
	"errors"
	"fmt"

	entSql "entgo.io/ent/dialect/sql"
	"github.com/go-kratos/kratos/v2/log"
	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent"
)

// QueryAllChildrenIds queries all descendant IDs for a given parent ID using a recursive CTE.
// This is a workaround for the bug in github.com/tx7do/go-crud/entgo@v0.0.38
// where the wrong sql.Rows type is used (database/sql instead of entgo.io/ent/dialect/sql).
func QueryAllChildrenIds(ctx context.Context, entClient *entCrud.EntClient[*ent.Client], tableName string, parentID uint32) ([]uint32, error) {
	if entClient == nil {
		return nil, errors.New("entClient is nil")
	}

	// PostgreSQL recursive CTE query to find all descendants
	query := fmt.Sprintf(`
		WITH RECURSIVE all_descendants AS (
			SELECT id, parent_id
			FROM %s
			WHERE parent_id = $1
			UNION ALL
			SELECT p.id, p.parent_id
			FROM %s p
			INNER JOIN all_descendants ad ON p.parent_id = ad.id
		)
		SELECT id FROM all_descendants;
	`, tableName, tableName)

	// Use ent's Rows type, not database/sql.Rows
	rows := &entSql.Rows{}
	if err := entClient.Query(ctx, query, []any{parentID}, rows); err != nil {
		log.Errorf("query child nodes failed: %s", err.Error())
		return nil, fmt.Errorf("query child nodes failed: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Errorf("close rows failed: %s", err.Error())
		}
	}()

	childIDs := make([]uint32, 0)
	for rows.Next() {
		var id uint32
		if err := rows.Scan(&id); err != nil {
			log.Errorf("scan child node failed: %s", err.Error())
			return nil, errors.New("scan child node failed")
		}
		childIDs = append(childIDs, id)
	}

	if err := rows.Err(); err != nil {
		log.Errorf("rows iteration error: %s", err.Error())
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return childIDs, nil
}
