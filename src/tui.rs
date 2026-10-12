use crate::{
    Severity, risk,
    scan::{ScanSession, ScanStep, StepStatus},
};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend, TestBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Wrap},
};
use std::{
    env, io,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
pub struct TerminalCapabilities {
    pub truecolor: bool,
    pub enhanced: bool,
    pub reduced_motion: bool,
}
impl TerminalCapabilities {
    pub fn detect() -> Self {
        let term = env::var("TERM").unwrap_or_default();
        let program = env::var("TERM_PROGRAM").unwrap_or_default().to_lowercase();
        let enhanced =
            term.contains("kitty") || program.contains("ghostty") || program.contains("kitty");
        let truecolor = enhanced
            || env::var("COLORTERM").is_ok_and(|v| v.contains("truecolor") || v.contains("24bit"));
        Self {
            truecolor,
            enhanced,
            reduced_motion: env::var("NO_COLOR").is_ok(),
        }
    }
    pub const fn enhanced() -> Self {
        Self {
            truecolor: true,
            enhanced: true,
            reduced_motion: false,
        }
    }
    pub const fn basic() -> Self {
        Self {
            truecolor: false,
            enhanced: false,
            reduced_motion: true,
        }
    }
}

pub fn marker_for(status: &str, tick: usize, reduced: bool) -> &'static str {
    match status {
        "running" if reduced => "[~]",
        "running" => ["[|]", "[/]", "[-]", "[\\]"][tick % 4],
        "completed" => "[+]",
        "failed" => "[-]",
        "skipped" => "[?]",
        "locked" => "[x]",
        _ => "[*]",
    }
}
fn marker(step: &ScanStep, tick: usize, reduced: bool) -> &'static str {
    match step.status {
        StepStatus::Running => marker_for("running", tick, reduced),
        StepStatus::Completed => marker_for("completed", tick, reduced),
        StepStatus::Failed => marker_for("failed", tick, reduced),
        StepStatus::Skipped => marker_for("skipped", tick, reduced),
        StepStatus::Locked => marker_for("locked", tick, reduced),
        StepStatus::Queued => marker_for("queued", tick, reduced),
    }
}
fn status_color(step: &ScanStep, caps: TerminalCapabilities) -> Color {
    match step.status {
        StepStatus::Completed => rgb(caps, 57, 255, 20, Color::Green),
        StepStatus::Running => rgb(caps, 0, 229, 255, Color::Cyan),
        StepStatus::Failed => rgb(caps, 255, 45, 85, Color::Red),
        StepStatus::Locked => Color::DarkGray,
        _ => rgb(caps, 180, 255, 40, Color::Green),
    }
}
fn rgb(c: TerminalCapabilities, r: u8, g: u8, b: u8, fallback: Color) -> Color {
    if c.truecolor {
        Color::Rgb(r, g, b)
    } else {
        fallback
    }
}

pub fn render_snapshot(
    session: &ScanSession,
    width: u16,
    height: u16,
    tick: usize,
    caps: TerminalCapabilities,
) -> String {
    render_snapshot_scrolled(session, width, height, tick, caps, 0)
}

pub fn render_snapshot_scrolled(
    session: &ScanSession,
    width: u16,
    height: u16,
    tick: usize,
    caps: TerminalCapabilities,
    scroll: u16,
) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|f| draw_scrolled(f, session, tick, caps, false, scroll))
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..height {
        for x in 0..width {
            out.push_str(buffer[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

pub fn draw(
    frame: &mut Frame,
    session: &ScanSession,
    tick: usize,
    caps: TerminalCapabilities,
    consent_modal: bool,
) {
    draw_scrolled(frame, session, tick, caps, consent_modal, 0)
}

fn draw_scrolled(
    frame: &mut Frame,
    session: &ScanSession,
    tick: usize,
    caps: TerminalCapabilities,
    consent_modal: bool,
    evidence_scroll: u16,
) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Rgb(2, 4, 8))),
        area,
    );
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(12),
            Constraint::Length(3),
        ])
        .split(area);
    let title = if area.width >= 90 {
        " NULLTRACE // FORENSIC OPERATIONS CONSOLE  //  EVIDENCE MATRIX "
    } else {
        " NULLTRACE // TASKS "
    };
    let logo = Paragraph::new(vec![
        gradient_line("N U L L T R A C E", caps),
        Line::from(vec![
            Span::styled("[*] ", Style::default().fg(Color::Green)),
            Span::raw(crate::files::visible(session.target())),
        ]),
        Line::from("OFFLINE FIRST  •  ONLINE BY CONSENT  •  ZERO FABRICATED INTEL"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(rgb(caps, 122, 0, 255, Color::Magenta))),
    );
    frame.render_widget(logo, rows[0]);
    if area.width >= 90 {
        draw_wide(frame, rows[1], session, tick, caps, evidence_scroll)
    } else {
        draw_compact(frame, rows[1], session, tick, caps, evidence_scroll)
    }
    let complete = session.offline_complete();
    let footer = if complete
        && session.phase() == crate::JobPhase::OfflineComplete
        && !session.has_online_checks()
    {
        " LOCAL REPORT READY  •  [↑↓] evidence  •  [q] quit "
    } else if complete && session.phase() == crate::JobPhase::OfflineComplete {
        " OFFLINE REPORT READY  ──  Press ENTER for online enrichment  •  [q] quit "
    } else {
        " [q] quit  •  [↑↓] navigate  •  evidence is state-backed "
    };
    frame.render_widget(
        Paragraph::new(footer)
            .style(Style::default().fg(if complete {
                Color::Yellow
            } else {
                Color::DarkGray
            }))
            .block(Block::default().borders(Borders::ALL)),
        rows[2],
    );
    if consent_modal {
        draw_consent(frame, area, caps);
    }
}
fn draw_wide(
    frame: &mut Frame,
    area: Rect,
    s: &ScanSession,
    tick: usize,
    c: TerminalCapabilities,
    scroll: u16,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(area);
    draw_tree(frame, cols[0], s, tick, c);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(cols[1]);
    draw_evidence(frame, right[0], s, c, scroll);
    draw_events(frame, right[1], s, c);
}
fn draw_compact(
    frame: &mut Frame,
    area: Rect,
    s: &ScanSession,
    tick: usize,
    c: TerminalCapabilities,
    scroll: u16,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);
    draw_tree(frame, rows[0], s, tick, c);
    draw_evidence(frame, rows[1], s, c, scroll);
}
fn draw_tree(frame: &mut Frame, area: Rect, s: &ScanSession, tick: usize, c: TerminalCapabilities) {
    let mut items = vec![ListItem::new(Line::styled(
        "▼ OFFLINE ANALYSIS",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))];
    for step in s.steps().iter().filter(|v| !v.online) {
        items.push(step_item(step, tick, c));
        if !step.detail.is_empty() {
            items.push(step_detail_item(step));
        }
    }
    let online_title =
        if s.phase() == crate::JobPhase::OnlineRunning || s.phase() == crate::JobPhase::Complete {
            "▶ ONLINE INTELLIGENCE"
        } else {
            "▶ ONLINE INTELLIGENCE [LOCKED]"
        };
    if s.has_online_checks() {
        items.push(ListItem::new(Line::styled(
            online_title,
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )));
        for step in s.steps().iter().filter(|v| v.online) {
            items.push(step_item(step, tick, c));
            if !step.detail.is_empty() {
                items.push(step_detail_item(step));
            }
        }
    }
    let settled = s
        .steps()
        .iter()
        .filter(|v| {
            matches!(
                v.status,
                StepStatus::Completed | StepStatus::Failed | StepStatus::Skipped
            )
        })
        .count();
    let gauge = Gauge::default()
        .ratio(settled as f64 / s.steps().len() as f64)
        .label(format!("{settled}/{} CHECKS", s.steps().len()))
        .gauge_style(Style::default().fg(rgb(c, 0, 229, 255, Color::Cyan)));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(1)])
        .split(area);
    frame.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" LIVE EXECUTION TREE ")
                .border_style(Style::default().fg(Color::Green)),
        ),
        chunks[0],
    );
    frame.render_widget(gauge, chunks[1]);
}
fn step_item(step: &ScanStep, tick: usize, c: TerminalCapabilities) -> ListItem<'static> {
    let duration = if step.elapsed_ms > 0 {
        format!("  {}ms", step.elapsed_ms)
    } else {
        String::new()
    };
    ListItem::new(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            marker(step, tick, c.reduced_motion),
            Style::default()
                .fg(status_color(step, c))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" {}{}", step.label, duration)),
    ]))
}
fn step_detail_item(step: &ScanStep) -> ListItem<'static> {
    ListItem::new(Line::styled(
        format!("      └─ {}", step.detail),
        Style::default().fg(Color::DarkGray),
    ))
}
fn draw_evidence(
    frame: &mut Frame,
    area: Rect,
    s: &ScanSession,
    c: TerminalCapabilities,
    scroll: u16,
) {
    let summary = risk::summarize(s.findings());
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" RISK {:02}/100 ", summary.score),
                Style::default()
                    .bg(if summary.score == 0 {
                        Color::DarkGray
                    } else {
                        risk_color(summary.score, c)
                    })
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("   {} finding(s)", s.findings().len())),
        ]),
        Line::raw(""),
    ];
    let checked = s
        .steps()
        .iter()
        .filter(|v| v.status == StepStatus::Completed)
        .count();
    let missing = s
        .steps()
        .iter()
        .filter(|v| matches!(v.status, StepStatus::Skipped | StepStatus::Failed))
        .count();
    lines.push(Line::styled(
        format!(
            "Coverage: {checked}/{} checked; {missing} unavailable",
            s.steps().len()
        ),
        Style::default().fg(Color::Yellow),
    ));
    lines.push(Line::styled(
        "Heuristic score; zero does not establish safety",
        Style::default().fg(Color::DarkGray),
    ));
    if s.findings().is_empty() {
        lines.push(Line::styled(
            "[?] No heuristic indicators detected",
            Style::default().fg(Color::DarkGray),
        ));
    }
    for f in s.findings() {
        let m = if f.severity == Severity::High || f.severity == Severity::Critical {
            "[!]"
        } else {
            "[*]"
        };
        lines.push(Line::from(vec![
            Span::styled(m, Style::default().fg(Color::Yellow)),
            Span::raw(crate::files::visible(&format!(
                " {} [{:?}/{:?} +{}]  {}",
                f.rule_id, f.severity, f.confidence, f.weight, f.summary
            ))),
        ]));
        for ev in &f.evidence {
            lines.push(Line::styled(
                crate::files::visible(&format!("    └─ {ev}")),
                Style::default().fg(Color::DarkGray),
            ));
        }
    }
    if !s.observations().is_empty() {
        lines.push(Line::styled(
            "── RAW OBSERVATIONS",
            Style::default().fg(Color::Cyan),
        ));
        for observation in s.observations() {
            lines.push(Line::from(vec![
                Span::styled("[+] ", Style::default().fg(Color::Green)),
                Span::raw(crate::files::visible(&format!(
                    "{}: {}",
                    observation.label, observation.value
                ))),
            ]));
        }
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" EVIDENCE TREE ")
        .border_style(Style::default().fg(rgb(c, 255, 0, 170, Color::Magenta)));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let regions = Layout::vertical([Constraint::Length(4), Constraint::Min(0)]).split(inner);
    let body = lines.split_off(4);
    frame.render_widget(Paragraph::new(lines), regions[0]);
    frame.render_widget(
        Paragraph::new(body)
            .scroll((scroll, 0))
            .wrap(Wrap { trim: true }),
        regions[1],
    );
}
fn draw_events(frame: &mut Frame, area: Rect, s: &ScanSession, _c: TerminalCapabilities) {
    let lines: Vec<_> = s
        .events()
        .iter()
        .rev()
        .take(area.height.saturating_sub(2) as usize)
        .rev()
        .map(|v| Line::raw(crate::files::visible(v)))
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" LIVE STATUS // REAL EVENTS ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        area,
    );
}
fn draw_consent(frame: &mut Frame, area: Rect, c: TerminalCapabilities) {
    let popup = centered(62, 52, area);
    frame.render_widget(Clear, popup);
    let text = vec![
        gradient_line("NETWORK ENRICHMENT", c),
        Line::raw(""),
        Line::raw("  This stage may contact:"),
        Line::raw("  • DNS resolvers"),
        Line::raw("  • target host and redirect destinations"),
        Line::raw("  • registry endpoints when available"),
        Line::raw(""),
        Line::styled(
            "  No local file content will be uploaded.",
            Style::default().fg(Color::Green),
        ),
        Line::raw(""),
        Line::styled(
            "       [ENTER] AUTHORIZE      [ESC] CANCEL",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" [!] CONSENT REQUIRED ")
                .border_style(Style::default().fg(Color::Yellow)),
        ),
        popup,
    );
}
fn centered(px: u16, py: u16, r: Rect) -> Rect {
    let v = Layout::vertical([
        Constraint::Percentage((100 - py) / 2),
        Constraint::Percentage(py),
        Constraint::Percentage((100 - py) / 2),
    ])
    .split(r);
    Layout::horizontal([
        Constraint::Percentage((100 - px) / 2),
        Constraint::Percentage(px),
        Constraint::Percentage((100 - px) / 2),
    ])
    .split(v[1])[1]
}
fn gradient_line(text: &str, c: TerminalCapabilities) -> Line<'static> {
    let n = text.chars().count().max(1);
    Line::from(
        text.chars()
            .enumerate()
            .map(|(i, ch)| {
                let t = i as f32 / n as f32;
                let color = if c.truecolor {
                    Color::Rgb((50.0 + 170.0 * t) as u8, (255.0 - 120.0 * t) as u8, 255)
                } else {
                    Color::Cyan
                };
                Span::styled(
                    ch.to_string(),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                )
            })
            .collect::<Vec<_>>(),
    )
}
fn risk_color(score: u8, c: TerminalCapabilities) -> Color {
    if score >= 60 {
        rgb(c, 255, 45, 85, Color::Red)
    } else if score >= 25 {
        rgb(c, 255, 190, 0, Color::Yellow)
    } else {
        rgb(c, 57, 255, 20, Color::Green)
    }
}

struct TerminalRestore;
impl Drop for TerminalRestore {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

pub fn run(mut session: ScanSession) -> Result<ScanSession> {
    enable_raw_mode()?;
    let _restore = TerminalRestore;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_loop(&mut terminal, &mut session);
    result?;
    Ok(session)
}
fn run_loop<B: Backend>(terminal: &mut Terminal<B>, session: &mut ScanSession) -> Result<()>
where
    B::Error: Send + Sync + 'static,
{
    let caps = TerminalCapabilities::detect();
    let started = Instant::now();
    let (worker_tx, worker_rx) = std::sync::mpsc::channel();
    let mut working = false;
    let mut consent = false;
    let mut evidence_scroll = 0u16;
    loop {
        let tick = (started.elapsed().as_millis() / 140) as usize;
        terminal.draw(|f| draw_scrolled(f, session, tick, caps, consent, evidence_scroll))?;
        if let Ok(updated) = worker_rx.try_recv() {
            *session = updated;
            working = false;
        }
        if !working
            && matches!(
                session.phase(),
                crate::JobPhase::OfflineRunning | crate::JobPhase::OnlineRunning
            )
        {
            // Publish Running before the expensive part runs on the next worker turn.
            let mut owned = session.clone();
            let tx = worker_tx.clone();
            working = true;
            std::thread::spawn(move || {
                if owned.phase() == crate::JobPhase::OfflineRunning {
                    owned.run_next_offline();
                } else {
                    owned.run_next_online();
                }
                let _ = tx.send(owned);
            });
        }
        if event::poll(Duration::from_millis(60))?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Enter if consent => {
                    let token = session.authorize_online()?;
                    session.begin_online_with(token)?;
                    consent = false;
                }
                KeyCode::Enter
                    if session.phase() == crate::JobPhase::OfflineComplete
                        && session.has_online_checks() =>
                {
                    session.request_online_consent()?;
                    consent = true;
                }
                KeyCode::Esc if consent => {
                    session.cancel_online_consent()?;
                    consent = false;
                }
                KeyCode::Home => evidence_scroll = 0,
                KeyCode::PageUp => evidence_scroll = evidence_scroll.saturating_sub(8),
                KeyCode::PageDown => evidence_scroll = evidence_scroll.saturating_add(8),
                KeyCode::Up => evidence_scroll = evidence_scroll.saturating_sub(1),
                KeyCode::Down => evidence_scroll = evidence_scroll.saturating_add(1),
                _ => {}
            }
        }
    }
    Ok(())
}
