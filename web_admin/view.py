from pathlib import Path


class AdminView:
    def __init__(self, ui_path: Path):
        self.ui_path = ui_path

    def render_index(self) -> str:
        return self.ui_path.read_text(encoding="utf-8")
