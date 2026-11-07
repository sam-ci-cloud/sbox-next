"""Public source boundaries shared by release packaging and validation."""
from pathlib import Path
import subprocess

INTERNAL={'AGENTS.md','CONTINUITY.md','PLAN.md','DECISIONS.md','STATE.json','KNOWN_BLOCKERS.md','MASTER_BRIEF.md','BASELINE_INVENTORY.md','UX_RESEARCH.md'}
EXCLUDED={'.git','.build','.cache','.codex-private','__pycache__','dist','.venv','node_modules','.private','private','evidence'}

def is_public(name):
 p=Path(name)
 return not EXCLUDED.intersection(p.parts) and not (len(p.parts)==1 and p.name in INTERNAL)

def tracked_files(root):
 try:
  names=subprocess.check_output(['git','ls-files','-z','--full-name'],cwd=root,stderr=subprocess.DEVNULL).decode().split('\0')
  gitroot=Path(subprocess.check_output(['git','rev-parse','--show-toplevel'],cwd=root).decode().strip())
  paths=(gitroot/name for name in names if name and (gitroot/name).is_relative_to(root) and is_public((gitroot/name).relative_to(root).as_posix()))
 except (FileNotFoundError,subprocess.CalledProcessError):
  # A delivered source archive has no .git directory. Keep its public checks
  # and repackaging fully offline and self-contained.
  paths=(path for path in root.rglob('*') if is_public(path.relative_to(root).as_posix()))
 return sorted(path for path in paths if path.is_file() and not path.is_symlink())
