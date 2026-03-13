// Package shared provides shared types for the Shield dashboard.
package shared

import "fmt"

// PaginationMeta holds pagination metadata for list pages.
type PaginationMeta struct {
	Total       int64
	Limit       int
	Offset      int
	TotalPages  int
	CurrentPage int
	HasPrev     bool
	HasNext     bool
}

// NewPaginationMeta creates pagination metadata from totals and current offset/limit.
func NewPaginationMeta(total int64, limit, offset int) PaginationMeta {
	if limit <= 0 {
		limit = 20
	}
	totalPages := int(total) / limit
	if int(total)%limit != 0 {
		totalPages++
	}
	page := (offset / limit) + 1
	return PaginationMeta{
		Total:       total,
		Limit:       limit,
		Offset:      offset,
		TotalPages:  totalPages,
		CurrentPage: page,
		HasPrev:     offset > 0,
		HasNext:     int64(offset+limit) < total,
	}
}

// PrevOffset returns the offset for the previous page.
func (p PaginationMeta) PrevOffset() int {
	o := p.Offset - p.Limit
	if o < 0 {
		return 0
	}
	return o
}

// NextOffset returns the offset for the next page.
func (p PaginationMeta) NextOffset() int {
	return p.Offset + p.Limit
}

// PageInfo returns a human-readable page info string.
func (p PaginationMeta) PageInfo() string {
	if p.Total == 0 {
		return "No items"
	}
	start := p.Offset + 1
	end := p.Offset + p.Limit
	if int64(end) > p.Total {
		end = int(p.Total)
	}
	return fmt.Sprintf("Showing %d–%d of %d", start, end, p.Total)
}

// EntityCounts holds entity counts for the overview dashboard.
type EntityCounts struct {
	Instincts  int64
	Awareness  int64
	Boundaries int64
	Values     int64
	Judgments  int64
	Reflexes   int64
	Profiles   int64
	Scans      int64
	Policies   int64
}
