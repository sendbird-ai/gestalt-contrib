package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/valon-technologies/gestalt/server/core"
	"github.com/valon-technologies/gestalt/server/core/catalog"
	"github.com/valon-technologies/gestalt/server/services/identity/principal"
	"github.com/valon-technologies/gestalt/server/services/invocation"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

// Workspace MCP handshake tools. Hosts such as Muxy and Cursor require
// tools/list to finish before they mark the server connected, so this set is
// static and does not walk app catalogs.
const (
	SearchToolName         = "gestalt_search"
	DescribeToolName       = "gestalt_describe"
	InvokeToolName         = "gestalt_invoke"
	ReadOnlyInvokeToolName = "gestalt_invoke_read_only"
)

// workspaceFrontDoorInstructions is returned on initialize so hosts do not
// treat the handshake tools as an inventory of app operations.
const workspaceFrontDoorInstructions = "tools/list is the connect handshake: gestalt_search, gestalt_describe, gestalt_invoke, and gestalt_invoke_read_only. Search to find operations you may use and describe for an operation's schema. Use gestalt_invoke for any authorized operation; gestalt_invoke_read_only accepts only operations with readOnly: true or annotations.readOnlyHint: true in the app catalog. App operations are not listed; these names are reserved for the workspace front door."

const (
	defaultSearchLimit = 20
	maxSearchLimit     = 100
	liveSearchTimeout  = 8 * time.Second
)

const catalogInstanceToolPropertyJSON = `"_instance": {"type": "string", "description": "Optional. Use when the app exposes more than one catalog instance."}`

var (
	searchToolSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Text to match against app and operation names, titles, and descriptions."
    },
    "app": {
      "type": "string",
      "description": "If set, search only this app and load its current catalog. If omitted, search uses each app's static catalog."
    },
    "limit": {
      "type": "integer",
      "description": "Maximum number of operations to return. Defaults to 20, max 100."
    },
    ` + catalogInstanceToolPropertyJSON + `
  }
}`)
	describeToolSchema = json.RawMessage(`{
  "type": "object",
  "required": ["app", "operation"],
  "properties": {
    "app": {"type": "string", "description": "App name, for example linear."},
    "operation": {"type": "string", "description": "Operation id, for example search_issues."},
    ` + catalogInstanceToolPropertyJSON + `
  }
}`)
	invokeToolSchema = json.RawMessage(`{
  "type": "object",
  "required": ["app", "operation"],
  "properties": {
    "app": {"type": "string", "description": "App name, for example linear."},
    "operation": {"type": "string", "description": "Operation id, for example search_issues."},
    "arguments": {"type": "object", "description": "Arguments for the operation."},
    ` + catalogInstanceToolPropertyJSON + `
  }
}`)
)

func WorkspaceFrontDoorToolNames() []string {
	return []string{DescribeToolName, InvokeToolName, ReadOnlyInvokeToolName, SearchToolName}
}

func workspaceFrontDoorTools() []mcpgo.Tool {
	readOnlyInvoke := mcpgo.NewToolWithRawSchema(ReadOnlyInvokeToolName, "Invoke a workspace app operation only when its catalog marks it read-only. Pass app, operation, and arguments.", invokeToolSchema)
	readOnlyInvoke.Annotations.ReadOnlyHint = mcpgo.ToBoolPtr(true)
	return []mcpgo.Tool{
		mcpgo.NewToolWithRawSchema(DescribeToolName, "Return one workspace operation's schema. Use this before gestalt_invoke when you need argument names.", describeToolSchema),
		mcpgo.NewToolWithRawSchema(InvokeToolName, "Invoke a workspace app operation. Pass app, operation, and arguments. Authorization is enforced on this call.", invokeToolSchema),
		readOnlyInvoke,
		mcpgo.NewToolWithRawSchema(SearchToolName, "Search workspace apps and operations the caller may use. Pass query, app, or both. Then call gestalt_describe, gestalt_invoke, or gestalt_invoke_read_only.", searchToolSchema),
	}
}

type SearchHit struct {
	App             string `json:"app"`
	Operation       string `json:"operation"`
	CatalogInstance string `json:"_instance,omitempty"`
	Title           string `json:"title,omitempty"`
	Description     string `json:"description,omitempty"`
}

type SearchUnavailable struct {
	App   string `json:"app"`
	Error string `json:"error"`
}

type SearchResult struct {
	Results     []SearchHit         `json:"results"`
	Unavailable []SearchUnavailable `json:"unavailable,omitempty"`
	Hint        string              `json:"hint,omitempty"`
	Truncated   bool                `json:"truncated,omitempty"`
}

type searchCandidate struct {
	hit   SearchHit
	query invocation.OperationAccessQuery
	score int
	// direct separates "this is what you asked for" from "this is in an app
	// you named"; see searchField.weak.
	direct bool
}

type describeResult struct {
	App             string          `json:"app"`
	Operation       string          `json:"operation"`
	CatalogInstance string          `json:"_instance,omitempty"`
	Title           string          `json:"title,omitempty"`
	Description     string          `json:"description,omitempty"`
	InputSchema     json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema    json.RawMessage `json:"outputSchema,omitempty"`
}

func (h *StatelessHTTPHandler) callSearch(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	p := principal.FromContext(ctx)
	if p == nil {
		return mcpgo.NewToolResultError("not authenticated"), nil
	}
	args := req.GetArguments()
	query := stringArg(args, "query")
	appFilter := stringArg(args, "app")
	instance := stringArg(args, "_instance")
	limit := intArg(args, "limit", defaultSearchLimit)
	if limit < 1 {
		limit = defaultSearchLimit
	}
	if limit > maxSearchLimit {
		limit = maxSearchLimit
	}
	if instance != "" && appFilter == "" {
		return mcpgo.NewToolResultError("app is required when _instance is set"), nil
	}
	if query == "" && appFilter == "" {
		return toolJSONResult(SearchResult{
			Results: []SearchHit{},
			Hint:    "Pass query or app to search workspace operations.",
		}), nil
	}

	candidates := make([]searchCandidate, 0)
	unavailable := make([]SearchUnavailable, 0)
	terms := searchTerms(query)
	for _, provName := range h.providerNames {
		if appFilter != "" && provName != appFilter {
			continue
		}
		if !principal.AllowsProviderPermission(p, provName) {
			continue
		}
		prov, ok := h.provider(ctx, provName)
		if !ok {
			continue
		}
		cat, liveErr := h.catalogForSearch(ctx, provName, prov, instance, appFilter != "")
		if liveErr != nil {
			unavailable = append(unavailable, SearchUnavailable{App: provName, Error: liveErr.Error()})
			continue
		}
		if cat == nil {
			continue
		}
		// Prepared once per app rather than once per operation: these five
		// fields are identical for every operation in the catalog.
		appFields := prepareSearchFields(
			searchField{text: provName, weight: searchWeightApp, weak: true},
			searchField{text: prov.DisplayName(), weight: searchWeightApp, weak: true},
			searchField{text: prov.Description(), weight: searchWeightApp, weak: true},
			searchField{text: cat.DisplayName, weight: searchWeightApp, weak: true},
			searchField{text: cat.Description, weight: searchWeightApp, weak: true},
		)
		for i := range cat.Operations {
			op := cat.Operations[i]
			if !catalog.OperationVisibleByDefault(op) || !catalogOperationProjectedToMCP(h.cfg, provName, op) {
				continue
			}
			// App fields are scored alongside the operation's own, rather than
			// acting as a gate that admits every operation in a matching app.
			// That keeps "search by app name" working while leaving those
			// operations in the lower tier, beneath anything that matched
			// directly.
			fields := prepareSearchFields(
				searchField{text: op.ID, weight: searchWeightOperationID},
				searchField{text: operationTitle(op), weight: searchWeightTitle},
				searchField{text: op.Description, weight: searchWeightDescription},
			)
			fields = append(fields, appFields...)
			score, direct := searchMatchScore(terms, fields)
			if score == 0 {
				continue
			}
			candidates = append(candidates, searchCandidate{
				score:  score,
				direct: direct,
				hit: SearchHit{
					App:             provName,
					Operation:       op.ID,
					CatalogInstance: instance,
					Title:           operationTitle(op),
					Description:     op.Description,
				},
				query: invocation.OperationAccessQuery{
					Provider:     provName,
					Operation:    op.ID,
					AllowedRoles: op.AllowedRoles,
					Metadata:     &op,
				},
			})
		}
	}

	// Relevance first. Sorting alphabetically meant the limit-20 page was filled
	// by whichever operations sorted early rather than whichever matched best,
	// so a good hit deeper in the catalog was truncated away unseen.
	sort.Slice(candidates, func(i, j int) bool {
		// Tier before score. An operation that matched the query itself is a
		// different kind of answer from one that merely lives in an app the
		// query named, and the two must not trade places on arithmetic.
		if candidates[i].direct != candidates[j].direct {
			return candidates[i].direct
		}
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if candidates[i].hit.App != candidates[j].hit.App {
			return candidates[i].hit.App < candidates[j].hit.App
		}
		return candidates[i].hit.Operation < candidates[j].hit.Operation
	})
	allowed, truncated, accessErr := h.pageSearchHits(ctx, p, candidates, limit)
	if accessErr != nil {
		return accessErr, nil
	}
	return toolJSONResult(SearchResult{Results: allowed, Unavailable: unavailable, Truncated: truncated}), nil
}

func (h *StatelessHTTPHandler) pageSearchHits(ctx context.Context, p *principal.Principal, candidates []searchCandidate, limit int) ([]SearchHit, bool, *mcpgo.CallToolResult) {
	hits := make([]SearchHit, 0, min(limit, len(candidates)))
	offset := 0
	for offset < len(candidates) && len(hits) < limit {
		need := limit - len(hits)
		take := min(len(candidates)-offset, invocation.MaxBatchedAccessChecks, max(need, defaultSearchLimit))
		window := candidates[offset : offset+take]
		queries := make([]invocation.OperationAccessQuery, len(window))
		for i := range window {
			queries[i] = window[i].query
		}
		ok, accessErr := h.allowedOperations(ctx, p, queries)
		if accessErr != nil {
			return nil, false, accessErr
		}
		consumed := 0
		for i := range window {
			consumed++
			if ok[i] {
				hits = append(hits, window[i].hit)
				if len(hits) == limit {
					break
				}
			}
		}
		offset += consumed
	}
	return hits, offset < len(candidates), nil
}

// allowedOperations answers the same evaluator questions FilterCatalogForPrincipal
// asks, then maps those answers to booleans so MCP handlers can return tool
// errors instead of JSON-RPC errors.
func (h *StatelessHTTPHandler) allowedOperations(ctx context.Context, p *principal.Principal, queries []invocation.OperationAccessQuery) ([]bool, *mcpgo.CallToolResult) {
	allowed := make([]bool, len(queries))
	if len(queries) == 0 {
		return allowed, nil
	}
	if h.cfg.OperationAccess == nil {
		for i := range allowed {
			allowed[i] = true
		}
		return allowed, nil
	}
	results, checkErr := h.cfg.OperationAccess.CheckOperationAccessMany(ctx, p, queries)
	if checkErr != nil {
		return nil, mcpgo.NewToolResultError("operation access is unavailable: " + checkErr.Error())
	}
	if len(results) != len(queries) {
		return nil, mcpgo.NewToolResultError(fmt.Sprintf("operation access returned %d decisions for %d operations", len(results), len(queries)))
	}
	for i := range results {
		allowed[i] = results[i].Err == nil
	}
	return allowed, nil
}

func (h *StatelessHTTPHandler) catalogForSearch(ctx context.Context, provName string, prov core.Provider, instance string, live bool) (*catalog.Catalog, error) {
	if !live {
		return projectCatalog(h.cfg, provName, prov, prov.Catalog()), nil
	}
	liveCtx, cancel := context.WithTimeout(ctx, liveSearchTimeout)
	defer cancel()
	raw, err := h.resolveCatalog(liveCtx, provName, prov, instance, true)
	if err != nil {
		return nil, err
	}
	return projectCatalog(h.cfg, provName, prov, raw), nil
}

func (h *StatelessHTTPHandler) callDescribe(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	p := principal.FromContext(ctx)
	if p == nil {
		return mcpgo.NewToolResultError("not authenticated"), nil
	}
	args := req.GetArguments()
	app := stringArg(args, "app")
	operation := stringArg(args, "operation")
	if app == "" || operation == "" {
		return mcpgo.NewToolResultError("app and operation are required"), nil
	}
	if !principal.AllowsProviderPermission(p, app) {
		return mcpgo.NewToolResultError("operation access denied"), nil
	}
	prov, ok := h.provider(ctx, app)
	if !ok {
		return mcpgo.NewToolResultError(fmt.Sprintf("app %q is not available", app)), nil
	}
	instance := normalizedSessionCatalogInstance(args["_instance"])
	rawCat, err := h.resolveCatalog(ctx, app, prov, instance, true)
	if err != nil {
		return mcpgo.NewToolResultError(err.Error()), nil
	}
	cat := projectCatalog(h.cfg, app, prov, rawCat)
	op, found := invocation.CatalogOperation(cat, operation)
	if !found || !catalogOperationProjectedToMCP(h.cfg, app, op) {
		return mcpgo.NewToolResultError(fmt.Sprintf("operation %q is not available on app %q", operation, app)), nil
	}
	allowed, accessErr := h.allowedOperations(ctx, p, []invocation.OperationAccessQuery{{
		Provider:     app,
		Operation:    operation,
		AllowedRoles: op.AllowedRoles,
		Metadata:     &op,
	}})
	if accessErr != nil {
		return accessErr, nil
	}
	if len(allowed) != 1 || !allowed[0] {
		return mcpgo.NewToolResultError("operation access denied"), nil
	}
	return toolJSONResult(describeResult{
		App:             app,
		Operation:       operation,
		CatalogInstance: instance,
		Title:           operationTitle(op),
		Description:     op.Description,
		InputSchema:     op.InputSchema,
		OutputSchema:    op.OutputSchema,
	}), nil
}

func (h *StatelessHTTPHandler) callInvoke(ctx context.Context, req mcpgo.CallToolRequest, requireReadOnly bool) (*mcpgo.CallToolResult, error) {
	args := req.GetArguments()
	app := stringArg(args, "app")
	operation := stringArg(args, "operation")
	if app == "" || operation == "" {
		return mcpgo.NewToolResultError("app and operation are required"), nil
	}
	nested := map[string]any{}
	if raw, ok := args["arguments"].(map[string]any); ok {
		for key, value := range raw {
			nested[key] = value
		}
	}
	if inst, ok := args["_instance"]; ok {
		nested["_instance"] = inst
	}
	inner := req
	inner.Params.Arguments = nested
	result, err := h.callResolvedAppTool(ctx, inner, statelessToolRef{provider: app, operation: operation}, requireReadOnly)
	if errors.Is(err, core.ErrNotFound) || errors.Is(err, invocation.ErrOperationNotFound) {
		return mcpgo.NewToolResultError(err.Error()), nil
	}
	return result, err
}

func operationTitle(op catalog.CatalogOperation) string {
	if strings.TrimSpace(op.Title) != "" {
		return op.Title
	}
	return op.ID
}

// searchField is one piece of text a query can match, weighted by how strong a
// signal a hit in it is: an operation ID is a far better match than a word
// buried in an app description.
type searchField struct {
	text   string
	weight int
	// weak marks a field describing the APP rather than the operation. A term
	// landing only in weak fields means "this operation belongs to an app you
	// named", not "this operation is what you asked for". Those are different
	// kinds of answer, so they are ranked as separate tiers rather than left to
	// compete on score.
	weak bool
}

// Operation identity beats prose. These weights order results WITHIN a tier;
// the guarantee that an app-name-only match never outranks a direct one is
// structural, carried by searchField.weak and the tier sort, not by the
// arithmetic here. Giving app fields equal standing is what let a one-word app
// query fill the page with alphabetically early operations while the relevant
// ones were truncated away.
const (
	searchWeightOperationID = 8
	searchWeightTitle       = 5
	searchWeightDescription = 2
	searchWeightApp         = 1
)

// searchTerms splits a query into distinct lowercase terms. Computed once per
// search, not per operation.
//
// Punctuation is trimmed from each end of a term. strings.Fields alone left it
// attached, and no catalog field contains any, so "issue," scored zero and
// "jira issue?" lost the full-coverage bonus that "jira issue" earns -- the
// same "one stray character voids the search" defect this scorer exists to
// fix, one level down.
//
// Only the ends are trimmed, rather than splitting on every non-word rune,
// because punctuation inside a term is usually part of an identifier the
// caller is naming exactly: splitting "items.list" into two terms makes it
// match every other operation in the items group, which is a worse answer than
// the one thing they asked for.
//
// Duplicates are dropped because each term contributes its own match bonus:
// repeating a word would otherwise buy rank without adding meaning.
func searchTerms(query string) []string {
	fields := strings.Fields(strings.ToLower(query))
	terms := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		f = strings.TrimFunc(f, func(r rune) bool { return !isSearchWordRune(r) })
		if f == "" {
			continue
		}
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		terms = append(terms, f)
	}
	return terms
}

// identifierWords inserts a separator at camelCase and letter/digit
// transitions so word-boundary matching works regardless of an app's naming
// convention.
//
// Matching runs on lowercased text, where "createJiraIssue" has become
// "createjiraissue" and every internal boundary is gone: "jira" could only ever
// score there as an incidental substring, while in "slack_send_message" it
// scores as a whole word. Atlassian's catalog is camelCase and Slack's is
// snake_case, so without this the snake_case app gets a head start on every
// multi-term query for a reason the caller cannot see.
func identifierWords(s string) string {
	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i, r := range runes {
		if i > 0 {
			var next rune
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			if needsWordSplit(runes[i-1], r, next) {
				b.WriteByte(' ')
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}

// needsWordSplit reports whether a word boundary falls before cur. next is the
// rune after cur, or 0 at the end of the identifier; it is what separates an
// acronym running into a word ("HTTPResponse") from one that does not
// ("getHTTP").
func needsWordSplit(prev, cur, next rune) bool {
	switch {
	case unicode.IsLower(prev) && unicode.IsUpper(cur):
		return true
	case unicode.IsUpper(prev) && unicode.IsUpper(cur) && unicode.IsLower(next):
		return true
	case unicode.IsLetter(prev) && unicode.IsDigit(cur):
		return true
	case unicode.IsDigit(prev) && unicode.IsLetter(cur):
		return true
	}
	return false
}

// prepareSearchFields lowercases each field once and, where an identifier
// carries internal word boundaries that lowercasing destroys, adds the split
// form alongside the raw one. Both are kept so that pasting an exact operation
// ID still scores as an exact match while "jira" can match inside it as a word.
//
// Done once per app and once per operation rather than once per term.
func prepareSearchFields(fields ...searchField) []searchField {
	prepared := make([]searchField, 0, len(fields)+2)
	for _, f := range fields {
		if f.text == "" {
			continue
		}
		lower := strings.ToLower(f.text)
		prepared = append(prepared, searchField{text: lower, weight: f.weight, weak: f.weak})
		if split := strings.ToLower(identifierWords(f.text)); split != lower {
			prepared = append(prepared, searchField{text: split, weight: f.weight, weak: f.weak})
		}
	}
	return prepared
}

// searchMatchScore scores fields against terms, returning 0 when nothing matched.
//
// Scoring rather than filtering is the whole point. This previously required
// the ENTIRE query to appear as one literal substring, so a single filler word
// voided the search: "jira issue" found six operations and "find jira issue"
// found none. Requiring every term instead would not have fixed that either,
// because "find" appears nowhere in any catalog. Here each term is scored
// independently, so filler words cost nothing and the operations matching the
// most meaningful terms rank highest. Word order stops mattering for the same
// reason.
//
// direct reports whether any term matched a field belonging to the operation
// itself. It tiers the results: see searchField.weak.
func searchMatchScore(terms []string, prepared []searchField) (score int, direct bool) {
	if len(terms) == 0 {
		return 1, true
	}
	matched := 0
	for _, term := range terms {
		best := 0
		for _, f := range prepared {
			text := f.text
			hit := 0
			switch {
			case text == term:
				hit = f.weight * 3
			case containsSearchWord(text, term):
				hit = f.weight * 2
			case strings.Contains(text, term):
				hit = f.weight
			}
			if hit == 0 {
				continue
			}
			if !f.weak {
				direct = true
			}
			best = max(best, hit)
		}
		if best > 0 {
			matched++
			score += best
		}
	}
	if matched == 0 {
		return 0, false
	}
	// Covering more of the query outweighs where any single term landed, so
	// "create issue" beats an operation that merely mentions "issue".
	score += matched * 10
	if matched == len(terms) {
		score += 25
	}
	return score, direct
}

// containsSearchWord reports whether needle appears in haystack on word
// boundaries, so "issue" matches "jira_issue" and "Create Issue" and ranks
// above an incidental substring such as "reissue".
func containsSearchWord(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); {
		j := strings.Index(haystack[i:], needle)
		if j < 0 {
			return false
		}
		start := i + j
		end := start + len(needle)
		startOK := start == 0
		if !startOK {
			prev, _ := utf8.DecodeLastRuneInString(haystack[:start])
			startOK = !isSearchWordRune(prev)
		}
		endOK := end == len(haystack)
		if !endOK {
			next, _ := utf8.DecodeRuneInString(haystack[end:])
			endOK = !isSearchWordRune(next)
		}
		if startOK && endOK {
			return true
		}
		i = start + 1
	}
	return false
}

// isSearchWordRune reports whether r is part of a word. Boundaries are decided
// on runes, not bytes: checking bytes would treat every UTF-8 continuation byte
// as a non-word character, so accented or CJK text adjacent to a match would
// look like a word boundary and promote an incidental substring to a word
// match.
func isSearchWordRune(r rune) bool {
	// Combining marks count: in decomposed text an accent follows its base
	// letter as a separate rune, and treating it as a boundary would split a
	// word in the middle.
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r)
}

func stringArg(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	raw, ok := args[key]
	if !ok || raw == nil {
		return ""
	}
	if value, ok := raw.(string); ok {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(fmt.Sprint(raw))
}

func intArg(args map[string]any, key string, fallback int) int {
	if args == nil {
		return fallback
	}
	switch value := args[key].(type) {
	case nil:
		return fallback
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		return int(value)
	case json.Number:
		n, err := value.Int64()
		if err != nil {
			return fallback
		}
		return int(n)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return fallback
		}
		return n
	default:
		return fallback
	}
}

func toolJSONResult(v any) *mcpgo.CallToolResult {
	raw, err := json.Marshal(v)
	if err != nil {
		return mcpgo.NewToolResultError(err.Error())
	}
	return mcpgo.NewToolResultText(string(raw))
}

// DecodeSearchToolResult reads gestalt_search's JSON body from a tools/call
// envelope. Tests and clients use this so they do not each invent a decoder.
func DecodeSearchToolResult(envelope map[string]any) (SearchResult, error) {
	if envelope == nil {
		return SearchResult{}, fmt.Errorf("missing MCP envelope")
	}
	if rpcErr, ok := envelope["error"]; ok {
		return SearchResult{}, fmt.Errorf("gestalt_search rpc error: %v", rpcErr)
	}
	result, _ := envelope["result"].(map[string]any)
	if result == nil {
		return SearchResult{}, fmt.Errorf("gestalt_search missing result")
	}
	if isError, _ := result["isError"].(bool); isError {
		return SearchResult{}, fmt.Errorf("gestalt_search tool error: %v", result)
	}
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		return SearchResult{Results: []SearchHit{}}, nil
	}
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	var body SearchResult
	if err := json.Unmarshal([]byte(text), &body); err != nil {
		return SearchResult{}, fmt.Errorf("decode gestalt_search: %w", err)
	}
	if body.Results == nil {
		body.Results = []SearchHit{}
	}
	return body, nil
}
