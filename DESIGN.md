# Net Stability Design System

## Product Feel

Net Stability is a desktop diagnostic tool for people who need clear network evidence before changing settings. The interface should feel calm, technical, and reversible: more maintenance console than marketing page.

## Color Tokens

- `background`: `#f6f7f9`
- `surface`: `#ffffff`
- `text`: `#172033`
- `muted-text`: `#40516f`
- `secondary-text`: `#556987`
- `log-background`: `#0f172a`
- `log-text`: `#e5eefb`

## Typography

- Primary UI font: Segoe UI on Windows, falling back to the Tk platform default elsewhere.
- Title: 24px bold.
- Lead/status text: 11px regular.
- Body and stage labels: 10px regular.
- Stage status: 10px bold.
- Log output: Consolas 10px where available, falling back to monospace.

## Spacing

- Window padding: 28px.
- Panel padding: 18px for status panels, 10px for log panels.
- Button padding: 14px by 8px for normal buttons, 24px by 18px for the primary action.
- Vertical rhythm: 6px between title and lead, 14-20px between major workflow regions.

## Components

- Primary action button: full-width, bold, reserved for the normal safe workflow.
- Secondary action grid: equal-width buttons for read-only diagnostics, app-only changes, restore, and backup inspection.
- Stage panel: a compact two-column progress list with label left and state right.
- Log panel: scrollable dark terminal-style text area showing the exact command output.

## Interaction Rules

- Read-only diagnostics must be presented before mutation-oriented actions.
- Mutating actions must keep explicit backup and restore language.
- Long-running commands stream real output and update stage state instead of hiding work behind a spinner.
- Error states use direct language and keep the log visible.

## Implementation Notes

- The GUI is standard-library Tkinter; do not add web-only dependencies for desktop UI polish.
- Keep colors and spacing aligned with the tokens above when changing `net_stability_gui.py`.
