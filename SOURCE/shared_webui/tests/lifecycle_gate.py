"""Nonvacuous fail-first gate: legacy baseline lacks this CLI deployment path."""
import pathlib,subprocess,sys,tempfile,unittest
root=pathlib.Path(sys.argv[1]).resolve();sys.argv=sys.argv[:1]
class Integration(unittest.TestCase):
    def test_unknown_webui_action_is_dispatched_to_lifecycle(self):
        source=(root/'src/manager.sh').read_text().removesuffix('main "$@"\n')
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'functions';p.write_text(source)
            command='source "$1"; webui_command() { printf "PANEL:%s" "$1"; }; main webui status'
            proc=subprocess.run(['bash','-c',command,'test',str(p)],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr[-500:]);self.assertEqual(proc.stdout,'PANEL:status')
unittest.main()
