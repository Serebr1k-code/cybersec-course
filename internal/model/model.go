// Package model defines the shared data types of the CTF learning tree.
package model

// Difficulty levels, ordered from easiest to hardest.
var DifficultyOrder = map[string]int{
	"beginner": 0,
	"easy":     1,
	"medium":   2,
	"hard":     3,
	"expert":   4,
}

// DifficultyColors maps a difficulty to its accent colour (dark theme tuned).
var DifficultyColors = map[string]string{
	"beginner": "#22c55e",
	"easy":     "#84cc16",
	"medium":   "#eab308",
	"hard":     "#f97316",
	"expert":   "#ef4444",
}

// LessonMeta is the front-matter of a lesson file.
type LessonMeta struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Category         string   `json:"category"`
	Parent           string   `json:"parent"`
	Difficulty       string   `json:"difficulty"`
	Order            int      `json:"order"`
	Tags             []string `json:"tags"`
	Prerequisites    []string `json:"prerequisites"`
	UsefulFor        []string `json:"useful_for"`
	EstimatedMinutes int      `json:"estimated_minutes"`
	Summary          string   `json:"summary"`
	Author           string   `json:"author,omitempty"`
	// Waystone marks this lesson as a GATE ("вейстоун"): its whole descendant
	// subtree stays locked (hidden by the frontend fog-of-war) until every task
	// listed in WaystoneTasks is completed. Empty WaystoneTasks => inert gate.
	Waystone bool `json:"waystone,omitempty"`
	// WaystoneTasks are the lesson ids (capstone lab lessons) the learner must
	// complete to unlock the waystone's subtree. N == len(WaystoneTasks).
	WaystoneTasks []string `json:"waystone_tasks,omitempty"`
}

// Section is one readable chunk of a lesson. Reading time is tracked per
// section so the UI knows exactly how far the reader has progressed.
type Section struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	Markdown        string `json:"markdown"`
	Words           int    `json:"words"`
	RequiredSeconds int    `json:"required_seconds"`
}

// QuizQuestion is one interactive quiz item. Answer is the 0-based index of
// the correct option; it is stored separately from the visible body so the
// reader never sees the key before submitting.
type QuizQuestion struct {
	Question    string   `json:"question"`
	Options     []string `json:"options"`
	Answer      int      `json:"answer"`
	Explanation string   `json:"explanation,omitempty"`
}

// Lab describes an optional interactive terminal lab attached to a lesson via
// its front-matter `lab:` block. When present, the frontend renders a terminal
// panel ("Лаборатория") and lazily loads the lab bundle (virtual-FS seed +
// captured tool fixtures) from GET /api/labs/{id}. The heavy terminal engine is
// code-split and only downloaded for lessons that actually carry a lab.
type Lab struct {
	// Kind is the lab engine kind; "shell" is the client-side virtual shell.
	Kind string `json:"kind"`
	// Title is an optional human label for the lab panel.
	Title string `json:"title,omitempty"`
	// Toolset lists the tool groups the author enabled (core, grep, net, ...).
	// Purely informational for the UI; the engine exposes everything it knows.
	Toolset []string `json:"toolset,omitempty"`
	// Workdir is the initial working directory inside the virtual FS.
	Workdir string `json:"workdir,omitempty"`
	// Files lists the seed files the student should start from (documentation).
	Files []string `json:"files,omitempty"`
	// Check is a shell command run inside the lab; exit code 0 == solved.
	Check string `json:"check,omitempty"`
	// Hints are progressive hints (weakest first, strongest last). The lab
	// never exposes the full spoiler automatically.
	Hints []string `json:"hints,omitempty"`
	// Bundle is the fixture-bundle id (defaults to the lesson id).
	Bundle string `json:"bundle,omitempty"`
}

// Lesson is a full lesson: metadata + rendered sections.
type Lesson struct {
	LessonMeta
	Slug     string         `json:"slug"`
	Sections []Section      `json:"sections"`
	Quiz     []QuizQuestion `json:"quiz"`
	Words    int            `json:"words"`
	Lab      *Lab           `json:"lab,omitempty"`
}

// TreeNode is a node of the learning tree (a lesson in graph form).
type TreeNode struct {
	ID         string      `json:"id"`
	Title      string      `json:"title"`
	Category   string      `json:"category"`
	Difficulty string      `json:"difficulty"`
	Parent     string      `json:"parent"`
	Order      int         `json:"order"`
	Depth      int         `json:"depth"`
	Sections   int         `json:"sections"`
	Words      int         `json:"words"`
	EstMinutes int         `json:"estimated_minutes"`
	Tags       []string    `json:"tags"`
	Children   []*TreeNode `json:"children"`
	// Waystone / WaystoneTasks mirror LessonMeta so /api/tree can drive the
	// frontend gate without a second request (see model.LessonMeta).
	Waystone      bool     `json:"waystone,omitempty"`
	WaystoneTasks []string `json:"waystone_tasks,omitempty"`
}

// Category is a top-level branch of the tree.
type Category struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Icon        string `json:"icon"`
	Description string `json:"description"`
	Count       int    `json:"count"`
}

// TreeResponse is what the /api/tree endpoint returns.
type TreeResponse struct {
	Categories []Category  `json:"categories"`
	Nodes      []*TreeNode `json:"nodes"`
	Total      int         `json:"total"`
}

// Edge is a parent -> child link for graph layout.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
}
