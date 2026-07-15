# Net Stability Design System

## Product Feel

Net Stability is a desktop diagnostic tool for people who need clear network evidence before changing settings. The interface should feel calm, technical, and reversible: more maintenance console than marketing page.

## Color Tokens

- `background`: `#f6f7f9`
- `surface`: `#ffffff`
- `text`: `#172033`
- `muted-text`: `#40516f`
- `secondary-text`: `#556987`
- `danger-text`: `#7f1d1d`
- `danger-surface`: `#e5e3df`
- `danger-border`: `#b9aaa7`
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

- Primary action button: full-width, bold, reserved for the normal read-only diagnostic workflow.
- Secondary action grid: equal-width buttons for focused diagnostics, confirmed system repair, restore, and backup inspection.
- Confirmed mutation button: the same dimensions as other secondary controls, with restrained danger text and border colors instead of a filled warning block.
- Stage panel: a compact two-column progress list with label left and state right.
- Log panel: scrollable dark terminal-style text area showing the exact command output.

## Interaction Rules

- Read-only diagnostics must be presented before mutation-oriented actions.
- Mutating actions must keep explicit backup and restore language and require confirmation before any background work starts.
- Confirmed mutations are non-cancellable once launched so snapshot and manifest bookkeeping cannot be interrupted by the GUI.
- npm configuration remains a separate CLI opt-in rather than part of the GUI system-repair action.
- Long-running commands stream real output and update stage state instead of hiding work behind a spinner.
- Error states use direct language and keep the log visible.

## Implementation Notes

- The GUI is standard-library Tkinter; do not add web-only dependencies for desktop UI polish.
- Command metadata, never button labels, determines confirmation, danger styling, and cancellation policy.
- Keep colors and spacing aligned with the tokens above when changing `net_stability_gui.py`.
