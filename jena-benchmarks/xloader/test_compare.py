# Licensed under the terms of http://www.apache.org/licenses/LICENSE-2.0
"""Checks for compare.py on synthetic run directories; these do not run Jena."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import compare  # noqa: E402

# Norwegian locale, as xloader prints it with nb_NO (spaces are U+00A0 in real logs).
NB_LOG = """\
Command /bin/gzip not found
20:52:27 INFO  Nodes           :: == Parse (nodes): 347,065 seconds : 229 392 099 triples/quads 660 949 TPS
20:54:23 INFO  Terms           :: == Index terms: 97,962 seconds : 51 145 822 indexed RDF terms : 522 099 PerSecond
20:54:23 INFO  Terms           :: ==-==-== NodeTable : 463,880 seconds - 0h 07m 43s at 494 507 terms per second
20:58:01 INFO  Data            :: ==-==-== Total: 229 392 099 tuples : 217,16 seconds : 1 056 332,50 tuples/sec [2026/09/29]
21:02:25 INFO  Index           :: ==-==-== Index SPO : 263,049 seconds - 0h 04m 23s at 870 602 TPS
21:11:46 INFO  Index           :: ==-==-== Index POS : 9598,112 seconds - 2h 39m 58s at 23 860 TPS
21:17:04 INFO  Index           :: ==-==-== Index OSP : 316,769 seconds - 0h 05m 16s at 722 959 TPS
21:17:04 INFO  Overall          1825 seconds
     1825.80 real      2665.27 user       213.89 sys
         13189840896  maximum resident set size
"""

# English locale.
EN_LOG = NB_LOG.replace("347,065", "347.065").replace("97,962", "97.962") \
    .replace("463,880", "463.880").replace("217,16", "217.16").replace("263,049", "263.049") \
    .replace("9598,112", "9,598.112").replace("316,769", "316.769") \
    .replace(" ", ",").replace("1,056,332,50", "1,056,332.50")

VERIFICATION = "-------------\n| triples   |\n=============\n| 229010967 |\n-------------\n"


class NumberTests(unittest.TestCase):
    def test_locales(self):
        cases = {"464,373": 464.373, "464.373": 464.373, "9598,112": 9598.112,
                 "9,598.112": 9598.112, "9.598,112": 9598.112, "1825": 1825.0,
                 "229 392 099": 229392099.0, "229,392,099": 229392099.0,
                 "218,24": 218.24, "1 056 332,50": 1056332.5}
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertAlmostEqual(compare.number(text), expected)

    def test_not_a_number(self):
        self.assertIsNone(compare.number(" "))


class LogTests(unittest.TestCase):
    def test_both_locales_parse_the_same(self):
        nb = compare.parse_loader_log(NB_LOG)
        en = compare.parse_loader_log(EN_LOG)
        self.assertEqual(nb, en)
        self.assertAlmostEqual(nb["parse"], 347.065)
        self.assertAlmostEqual(nb["node_table"], 463.880)
        self.assertAlmostEqual(nb["ingest"], 217.16)
        self.assertEqual(list(nb["indexes"]), ["SPO", "POS", "OSP"])
        self.assertAlmostEqual(nb["indexes"]["POS"], 9598.112)
        self.assertEqual(nb["terms"], 51145822)
        self.assertEqual(nb["overall"], 1825.0)
        self.assertEqual(nb["real"], 1825.80)
        self.assertEqual(nb["max_rss"], 13189840896)

    def test_incomplete_log(self):
        partial = compare.parse_loader_log(NB_LOG.split("21:11:46")[0])
        self.assertEqual(list(partial["indexes"]), ["SPO"])
        self.assertNotIn("overall", partial)

    def test_hms(self):
        self.assertEqual(compare.hms(263.049), "4:23")
        self.assertEqual(compare.hms(20287), "5:38:07")
        self.assertEqual(compare.hms(None), "")


class RunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="jena-compare-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def run_dir(self, name, label, elapsed, log=NB_LOG, count=VERIFICATION, status="counted",
                sort_output="sort (GNU coreutils) 9.12\n", compress=None, calls=6):
        directory = self.home / "runs" / "lexemes" / name
        directory.mkdir(parents=True)
        meta = {"label": label, "started_utc": name[:16], "status": status,
                "jena_home": "/bench/build/current", "threads": 2, "jvm_args": "-Xmx4G",
                "sort": {"output": sort_output, "executable": "/opt/homebrew/bin/gsort"},
                "sort_compress": compress or "as passed by xloader",
                "sort_compress_calls": {"compress": calls, "decompress": calls},
                "elapsed_seconds": elapsed}
        (directory / "run.json").write_text(json.dumps(meta))
        (directory / "loader.log").write_text(log)
        if count is not None:
            (directory / "verification.log").write_text(count)
        return directory

    def table(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = compare.main(["lexemes", "--home", str(self.home), *args])
        return code, out.getvalue()

    def test_markdown_table_with_reference(self):
        self.run_dir("20260929T184637Z-aaaaaaaa", "baseline", 1825.8)
        self.run_dir("20260929T191917Z-bbbbbbbb", "current-pigz", 1691.0,
                     log=NB_LOG.replace("1825.80 real", "1690.57 real")
                               .replace("Overall          1825", "Overall          1691"),
                     compress={"executable": "/opt/homebrew/bin/pigz"})
        code, text = self.table("--reference", "baseline")
        self.assertEqual(code, 0)
        lines = text.splitlines()
        self.assertEqual(len(lines), 4)
        self.assertIn("vs baseline", lines[0])
        self.assertIn("| pigz", lines[3])
        self.assertIn("-7%", lines[3])
        self.assertIn("229,010,967", lines[3])

    def test_slept_run_is_flagged_and_not_compared(self):
        self.run_dir("20260929T184637Z-aaaaaaaa", "baseline", 1825.8)
        self.run_dir("20260929T215408Z-cccccccc", "slept", 1342.8,
                     log=NB_LOG.replace("1825.80 real", "20287.67 real"))
        code, text = self.table("--reference", "baseline")
        row = text.splitlines()[3]
        self.assertIn("slept", row)
        self.assertNotIn("%", row)

    def test_reference_skips_flagged_runs(self):
        # The first run with the reference label slept; compare against the rerun.
        self.run_dir("20260929T184637Z-aaaaaaaa", "baseline", 1342.8,
                     log=NB_LOG.replace("1825.80 real", "20287.67 real"))
        self.run_dir("20260929T191917Z-bbbbbbbb", "baseline", 1825.8)
        self.run_dir("20260929T195114Z-dddddddd", "current-pigz", 1691.0,
                     log=NB_LOG.replace("1825.80 real", "1690.57 real")
                               .replace("Overall          1825", "Overall          1691"))
        code, text = self.table("--reference", "baseline")
        lines = text.splitlines()
        self.assertIn("vs baseline", lines[0])
        self.assertIn("+0%", lines[3])
        self.assertIn("-7%", lines[4])

    def test_differing_counts_are_flagged(self):
        self.run_dir("20260929T184637Z-aaaaaaaa", "a", 1825.8)
        self.run_dir("20260929T191917Z-bbbbbbbb", "b", 1825.8)
        self.run_dir("20260929T195114Z-dddddddd", "c", 1825.8, count=VERIFICATION.replace("229010967", "229010900"))
        code, text = self.table()
        self.assertIn("triples 229,010,900 != 229,010,967", text.splitlines()[4])
        self.assertNotIn("!=", text.splitlines()[2])

    def test_running_run_and_filters(self):
        self.run_dir("20260929T184637Z-aaaaaaaa", "baseline", 1825.8)
        self.run_dir("20260930T074510Z-eeeeeeee", "baseline-t8", None, count=None,
                     status="running", log=NB_LOG.split("20:58:01")[0])
        code, text = self.table("--label", "t8")
        self.assertEqual(len(text.splitlines()), 3)
        self.assertIn("running", text)
        code, text = self.table("--counted")
        self.assertNotIn("baseline-t8", text)

    def test_csv(self):
        self.run_dir("20260929T184637Z-aaaaaaaa", "baseline", 1825.8)
        code, text = self.table("--format", "csv")
        self.assertTrue(text.startswith("run,label,build,sort,compressor,threads,"))
        self.assertIn(",7:44,3:37,4:23,2:39:58,5:17,30:25,30:26,", text)

    def test_sorter_names(self):
        self.assertEqual(compare.sorter_name({"sort": {"output": "sort (uutils coreutils) 0.12.0\n",
                                                       "executable": "/x/tools/uu-sort-xloader"}}),
                         "uu 0.12.0 (uu-sort-xloader)")
        self.assertEqual(compare.sorter_name({"sort": {"output": "sort (GNU coreutils) 9.12\n",
                                                       "executable": "/opt/homebrew/bin/gsort"}}),
                         "GNU 9.12")

    def test_no_runs(self):
        with self.assertRaises(ValueError):
            compare.find_runs(self.home, "truthy")


if __name__ == "__main__":
    unittest.main()
