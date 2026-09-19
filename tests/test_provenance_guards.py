"""Structural guard regressions. These never execute destructive system operations."""
from pathlib import Path
import unittest

MAIN = (Path(__file__).resolve().parents[1] / "src" / "main.cpp").read_text(encoding="utf-8")


def body(signature):
    start = MAIN.index(signature + " {")
    return MAIN[start:MAIN.index("\n}", start)]


class ProvenanceGuards(unittest.TestCase):
    def test_live_actions_require_live_data_at_entry(self):
        for signature in ("void App::KillSelectedProcess(bool tree)", "void App::SuspendSelectedProcess()",
                          "void App::BlockSelectedIp()", "void App::UnblockSelectedIp()",
                          "void App::RunAiAnalysis(bool bulk)", "void App::FollowUpAi(int q)",
                          "void App::ShowProcessProperties()"):
            self.assertEqual(body(signature).splitlines()[1].strip(), "if (!RequireLiveData()) return;")
        self.assertIn("if (m_demo) return 0;", body("DWORD App::SelectedPid(std::wstring* nameOut) const"))

    def test_demo_does_not_feed_real_anomaly_or_rate_baselines(self):
        tick = body("void App::Tick(bool force)")
        demo = tick[tick.index("if (m_demo)"):tick.index("m_mon.Refresh();")]
        for operation in ("TickAnomaly(", "NoteNewConnections(", "PushRateSample(", "m_hist.Update("):
            self.assertNotIn(operation, demo)

    def test_demo_does_not_dispatch_live_requeries(self):
        guard = body("void App::OnCommand(int id)").split("switch (id)")[0]
        for action in ("IDM_THREAT_REFRESH", "IDM_CERT_REFRESH", "IDM_OPEN_FOLDER", "IDM_WHOIS"):
            self.assertIn(action, guard)
        self.assertIn("RequireLiveData(); return;", guard)

    def test_csv_origin_is_applied_before_encoding_or_writing(self):
        export = body("void App::ExportData()")
        self.assertLess(export.index("LabelCsvOrigin(out, m_demo)"), export.index("Narrow(out)"))

    def test_plugin_is_not_attributed_to_abuseipdb(self):
        self.assertNotIn("c.threatScore = t.pluginRisk", MAIN)
        self.assertIn("c.pluginRisk = t.pluginRisk", MAIN)
