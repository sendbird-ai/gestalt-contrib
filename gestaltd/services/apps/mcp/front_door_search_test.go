package mcp

import (
	"fmt"
	"testing"
)

// Fields as callSearch builds them: the operation's own text weighted above
// the app's, so an app-name match cannot outrank a direct operation match.
func opFields(app, appDesc, id, title, desc string) []searchField {
	return []searchField{
		{text: id, weight: searchWeightOperationID},
		{text: title, weight: searchWeightTitle},
		{text: desc, weight: searchWeightDescription},
		{text: app, weight: searchWeightApp, weak: true},
		{text: appDesc, weight: searchWeightApp, weak: true},
	}
}

func jiraCreateIssue() []searchField {
	return opFields("atlassian", "Jira and Confluence", "createJiraIssue", "Create Jira Issue", "Create a new issue in a Jira project")
}

func slackSendMessage() []searchField {
	return opFields("slack", "Slack workspace", "slack_send_message", "Send Message", "Send a message to a Slack channel or user")
}

func score(t *testing.T, query string, fields []searchField) int {
	t.Helper()
	s, _ := searchMatchScore(searchTerms(query), prepareSearchFields(fields...))
	return s
}

// direct reports the tier rather than the score: whether the query reached the
// operation itself or only the app around it.
func direct(t *testing.T, query string, fields []searchField) bool {
	t.Helper()
	_, d := searchMatchScore(searchTerms(query), prepareSearchFields(fields...))
	return d
}

// The original defect: requiring the whole query as one literal substring meant
// any filler word voided the search. "jira issue" found six operations and
// "find jira issue" found none, because that exact string appears nowhere.
func TestSearchFillerWordsDoNotVoidTheQuery(t *testing.T) {
	for _, query := range []string{
		"jira issue",
		"find jira issue",
		"find a jira issue by key",
		"can you create a jira issue for me",
	} {
		if got := score(t, query, jiraCreateIssue()); got == 0 {
			t.Errorf("query %q scored 0; filler words must not void a search", query)
		}
	}
	if got := score(t, "send message to slack channel", slackSendMessage()); got == 0 {
		t.Error(`"send message to slack channel" scored 0`)
	}
}

// "create issue" worked and "issue create" did not, because substring matching
// made word order significant.
func TestSearchIsOrderIndependent(t *testing.T) {
	forward := score(t, "create issue", jiraCreateIssue())
	reverse := score(t, "issue create", jiraCreateIssue())
	if forward == 0 || reverse == 0 {
		t.Fatalf("both orderings must match; got forward=%d reverse=%d", forward, reverse)
	}
	if forward != reverse {
		t.Errorf("word order changed the score: forward=%d reverse=%d", forward, reverse)
	}
}

// Covering more of the query has to win, or a page of weak partial matches
// buries the operation the user actually described.
func TestSearchPrefersMoreOfTheQueryMatched(t *testing.T) {
	both := score(t, "create issue", jiraCreateIssue())
	one := score(t, "create sandwich", jiraCreateIssue())
	if one == 0 {
		t.Fatal("a partial match should still score above zero")
	}
	if both <= one {
		t.Errorf("matching both terms (%d) must beat matching one (%d)", both, one)
	}
}

// An app-name match previously admitted EVERY operation in that app as an equal
// candidate, so the limit-20 page filled with alphabetically early operations
// and the relevant ones were truncated away. They should still be found, but
// ranked underneath anything that matched directly.
func TestSearchAppMatchRanksBelowOperationMatch(t *testing.T) {
	boards := opFields("atlassian", "Jira and Confluence", "listBoards", "List Boards", "List agile boards")

	if score(t, "atlassian", boards) == 0 {
		t.Fatal("an app-name query should still surface that app's operations")
	}
	// The tier, not the margin. Comparing the two scores only ever showed that
	// one number happened to exceed another by a point for one pair of queries.
	if direct(t, "atlassian", boards) {
		t.Error(`"atlassian" matches only the app, so it must not count as a direct hit`)
	}
	if !direct(t, "issue", jiraCreateIssue()) {
		t.Error(`"issue" matches the operation itself, so it must count as a direct hit`)
	}
}

// The margin between a direct match and an app-name-only match used to be one
// point, and came from the per-term bonuses rather than the field weights, so a
// second weak term flipped it. The tier has to hold no matter what the
// arithmetic does.
func TestSearchAppOnlyMatchStaysBelowDirectMatchUnderExtraTerms(t *testing.T) {
	boards := opFields("atlassian", "Jira and Confluence", "listBoards", "List Boards", "List agile boards")

	for _, query := range []string{
		"atlassian",
		"atlassian jira",
		"atlassian jira confluence",
		"atlassian jira confluence app",
	} {
		appScore := score(t, query, boards)
		if appScore == 0 {
			continue
		}
		if direct(t, query, boards) {
			t.Errorf("query %q reached only app fields but was tiered as direct", query)
		}
	}
}

// Identity beats prose: an operation named for the thing should beat one that
// merely mentions it in passing.
func TestSearchOperationIdentityBeatsDescription(t *testing.T) {
	byID := score(t, "issue", jiraCreateIssue())
	byDesc := score(t, "issue", opFields("atlassian", "Jira", "listBoards", "List Boards", "Boards group work into issue swimlanes"))
	if byID <= byDesc {
		t.Errorf("operation id/title match (%d) must beat a description-only match (%d)", byID, byDesc)
	}
}

func TestSearchNonMatchScoresZero(t *testing.T) {
	if got := score(t, "kubernetes deployment rollout", jiraCreateIssue()); got != 0 {
		t.Errorf("unrelated query should score 0, got %d", got)
	}
}

// An empty query is how "list everything in this app" is expressed, so it must
// match rather than filter.
func TestSearchEmptyQueryMatches(t *testing.T) {
	for _, q := range []string{"", "   "} {
		if got := score(t, q, jiraCreateIssue()); got == 0 {
			t.Errorf("empty query %q must match everything", q)
		}
	}
}

func TestContainsSearchWordRespectsBoundaries(t *testing.T) {
	for _, tc := range []struct {
		haystack, needle string
		want             bool
	}{
		{"create jira issue", "issue", true},
		{"jira_issue", "issue", true},
		{"create-issue", "issue", true},
		{"reissue the token", "issue", false}, // incidental substring
		{"issues", "issue", false},            // prefix of a longer word
		{"issue", "issue", true},
		{"", "issue", false},
		{"issue", "", false},
		// Boundaries are decided on runes. Checking bytes made every UTF-8
		// continuation byte look like a non-word character, so a substring
		// adjacent to non-ASCII text was wrongly promoted to a word match.
		{"caf\u00e9 order", "caf", false},
		{"caf\u00e9 order", "caf\u00e9", true},
		{"\u8ab2\u984c\u4f5c\u6210", "\u8ab2\u984c", false},
		{"send \u30e1\u30c3\u30bb\u30fc\u30b8", "\u30e1\u30c3\u30bb\u30fc\u30b8", true},
	} {
		if got := containsSearchWord(tc.haystack, tc.needle); got != tc.want {
			t.Errorf("containsSearchWord(%q, %q) = %v, want %v", tc.haystack, tc.needle, got, tc.want)
		}
	}
}

// A substring hit still counts, just below a word-boundary hit, so partial
// typing ("atlas" for "atlassian") keeps working.
func TestSearchSubstringStillMatchesBelowWordMatch(t *testing.T) {
	partial := score(t, "atlas", jiraCreateIssue())
	whole := score(t, "atlassian", jiraCreateIssue())
	if partial == 0 {
		t.Fatal(`"atlas" should still match the atlassian app`)
	}
	if whole <= partial {
		t.Errorf("a whole-word match (%d) should beat a substring match (%d)", whole, partial)
	}
}

// Punctuation used to survive tokenization while no catalog field contained
// any, so a trailing comma voided a term outright and a question mark cost the
// full-coverage bonus. Same defect as the one this scorer fixed, one level
// down.
func TestSearchPunctuationDoesNotVoidTerms(t *testing.T) {
	plain := score(t, "jira issue", jiraCreateIssue())
	if plain == 0 {
		t.Fatal("baseline query should match")
	}
	for _, query := range []string{
		"jira issue?",
		"jira, issue",
		"(jira) issue.",
		"jira issue!!",
	} {
		if got := score(t, query, jiraCreateIssue()); got != plain {
			t.Errorf("query %q scored %d, want %d -- punctuation must not change the terms", query, got, plain)
		}
	}
}

// Each matched term adds a bonus, so a repeated word would otherwise buy rank
// without adding meaning.
func TestSearchRepeatedTermsDoNotInflateScore(t *testing.T) {
	once := score(t, "issue", jiraCreateIssue())
	thrice := score(t, "issue issue issue", jiraCreateIssue())
	if once != thrice {
		t.Errorf("repeating a term changed the score: %d -> %d", once, thrice)
	}
}

// Lowercasing destroys camelCase boundaries, so without splitting, "jira"
// could only score as an incidental substring inside "createJiraIssue" while
// scoring as a whole word inside "create_jira_issue". Two apps, same operation
// shape, different rank purely by the vendor's naming convention.
func TestSearchScoreIsIndependentOfIdentifierConvention(t *testing.T) {
	camel := opFields("acme", "Acme", "createJiraIssue", "Create Jira Issue", "Create a new issue")
	snake := opFields("acme", "Acme", "create_jira_issue", "Create Jira Issue", "Create a new issue")

	for _, query := range []string{"jira issue", "jira", "issue", "create jira issue"} {
		if got, want := score(t, query, camel), score(t, query, snake); got != want {
			t.Errorf("query %q: camelCase scored %d, snake_case %d -- naming convention must not change rank", query, got, want)
		}
	}
}

// Splitting the identifier must not cost the exact match: pasting a whole
// operation ID is the one case where the raw form is what the caller typed.
func TestSearchExactOperationIDStillScoresHighest(t *testing.T) {
	exact := score(t, "createJiraIssue", jiraCreateIssue())
	partial := score(t, "issue", jiraCreateIssue())
	if exact <= partial {
		t.Errorf("an exact operation id (%d) must outscore a single term inside it (%d)", exact, partial)
	}
}

func TestIdentifierWords(t *testing.T) {
	for in, want := range map[string]string{
		"createJiraIssue":    "create Jira Issue",
		"create_jira_issue":  "create_jira_issue",
		"slack_send_message": "slack_send_message",
		"base64":             "base 64",
		"getHTTPResponse":    "get HTTP Response",
		"getHTTP":            "get HTTP",
		"":                   "",
	} {
		if got := identifierWords(in); got != want {
			t.Errorf("identifierWords(%q) = %q, want %q", in, got, want)
		}
	}
}

// Punctuation inside a term usually belongs to an identifier the caller is
// naming exactly. Splitting on it would make "items.list" match every
// operation in the items group, which is a worse answer than the one asked
// for, so only the ends of a term are trimmed.
func TestSearchDottedIdentifierStaysOneTerm(t *testing.T) {
	got := searchTerms("items.list")
	if len(got) != 1 || got[0] != "items.list" {
		t.Errorf("searchTerms of a dotted id = %v, want one term", got)
	}
	trimmed := searchTerms("(items.list),")
	if len(trimmed) != 1 || trimmed[0] != "items.list" {
		t.Errorf("surrounding punctuation should still be trimmed, got %v", trimmed)
	}
}

// Verbs look like stop words in ordinary prose but are among the most
// informative terms in a tool catalog: "get" is what separates get_tokens from
// list_tokens. Stripping them would trade the filler defect for a worse one.
func TestSearchTermsKeepsDomainVerbs(t *testing.T) {
	for _, verb := range []string{
		"get", "list", "create", "send", "read", "write", "find", "search",
		"delete", "update", "add", "remove", "query", "fetch", "resolve", "ask",
	} {
		got := searchTerms(verb + " something")
		if len(got) == 0 || got[0] != verb {
			t.Errorf("searchTerms(%q ...) dropped the verb; got %v", verb, got)
		}
	}
}

// Function words are removed so a long description cannot win by harvesting
// them. See searchStopWords.
func TestSearchTermsDropsFunctionWords(t *testing.T) {
	got := searchTerms("can you find me the design tokens")
	want := []string{"find", "design", "tokens"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("searchTerms = %v, want %v", got, want)
	}
}

// A query made entirely of function words still has to search for something.
// Returning nothing would turn a real question into an empty page, which reads
// to an agent as "not connected" -- the original reported defect.
func TestSearchTermsFallsBackWhenAllTermsAreStopWords(t *testing.T) {
	for _, q := range []string{"the", "is it", "can you"} {
		if got := searchTerms(q); len(got) == 0 {
			t.Errorf("searchTerms(%q) returned nothing; expected a fallback to the original terms", q)
		}
	}
}
