package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

func banner() {
	fmt.Println(titleStyle.Render("safe") + dimStyle.Render("  macOS adult-content lock"))
	fmt.Println(dimStyle.Render("multiple layers are aware; each one is a speed bump, the secret is the gate"))
	fmt.Println()
}

// plan holds the user's choices before execution.
type plan struct {
	source      listSource
	apply       bool
	burn        bool
	withProfile bool
	withPF      bool
	out         string
}

// runTUI drives the interactive flow and returns the chosen plan.
func runTUI(ctx context.Context) (*plan, []string, error) {
	banner()

	p := &plan{
		source:      defaultSource,
		withProfile: true,
		withPF:      true,
		out:         "out",
	}

	// Step 1: fetch the list with a spinner, so the user sees progress.
	fmt.Println(dimStyle.Render("Fetching blocklist from " + p.source.URL))
	domains, _, err := fetchWithSpinner(ctx, p.source)
	if err != nil || len(domains) == 0 {
		return nil, nil, fmt.Errorf("could not load a blocklist: %w", err)
	}

	// Step 2: the consent form.
	which := "default"
	confirmApply := false
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Ready").
				Description(fmt.Sprintf("%d domains loaded.", len(domains))),
			huh.NewSelect[string]().
				Title("Blocklist source").
				Description("StevenBlack is fetched now; the embedded list is the offline fallback.").
				Options(
					huh.NewOption("StevenBlack porn-only (fetched)", "default"),
					huh.NewOption("Embedded list (offline, small)", "embedded"),
				).
				Value(&which),
			huh.NewConfirm().
				Title("Install browser DoH-off policies (Chrome, Edge, Firefox, Zen)?").
				Description("Makes browsers respect /etc/hosts by disabling secure DNS.").
				Affirmative("Yes").
				Negative("Skip").
				Value(&p.withProfile),
			huh.NewConfirm().
				Title("Install pf firewall rules?").
				Description("Blocks plain DNS and known DoH resolver IPs. Needs sudo.").
				Affirmative("Yes").
				Negative("Skip").
				Value(&p.withPF),
			huh.NewConfirm().
				Title("Generate a secret and burn it after the run?").
				Description("The secret decrypts the rollback bundle. Burned = no clean undo.").
				Affirmative("Burn it").
				Negative("Keep it").
				Value(&p.burn),
		),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Proceed with apply?").
				Description("This writes /etc/hosts, locks it, and loads a system daemon.").
				Affirmative("Apply").
				Negative("Cancel").
				Value(&confirmApply),
		).WithHideFunc(func() bool { return !confirmApply }),
	)

	if err := form.Run(); err != nil {
		return nil, nil, err
	}
	if !confirmApply {
		return nil, nil, fmt.Errorf("cancelled")
	}
	if which == "embedded" {
		domains = fallbackDomains()
		p.source = listSource{Name: "embedded", URL: "embedded"}
	}
	p.apply = true

	fmt.Println()
	fmt.Println(okStyle.Render("✓") + " Plan confirmed. Running apply.")
	fmt.Println()
	return p, domains, nil
}

type fetchResult struct {
	domains []string
	desc    string
	err     error
}

func fetchWithSpinner(ctx context.Context, src listSource) ([]string, string, error) {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	m := fetchModel{spinner: s, src: src, done: make(chan fetchResult, 1)}
	go func() {
		d, desc, err := fetchDomains(ctx, src)
		m.done <- fetchResult{d, desc, err}
	}()

	prog := tea.NewProgram(m)
	final, err := prog.Run()
	if err != nil {
		return nil, "", err
	}
	fm := final.(fetchModel)
	if fm.result == nil {
		return nil, "", fmt.Errorf("fetch cancelled")
	}
	return fm.result.domains, fm.result.desc, fm.result.err
}

type fetchModel struct {
	spinner spinner.Model
	src     listSource
	done    chan fetchResult
	result  *fetchResult
}

func (m fetchModel) Init() tea.Cmd { return m.spinner.Tick }

func (m fetchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case fetchResult:
		m.result = &msg
		return m, tea.Quit
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m fetchModel) View() string {
	return fmt.Sprintf("  %s fetching %s", m.spinner.View(), dimStyle.Render(m.src.Name))
}

// pause waits for the user to press Enter, used between manual steps.
func pause(prompt string) {
	fmt.Println()
	fmt.Println(warnStyle.Render("▶ " + prompt))
	fmt.Print(dimStyle.Render("  press Enter to continue... "))
	var b [1]byte
	_, _ = os.Stdin.Read(b[:])
	_ = time.Now
}
