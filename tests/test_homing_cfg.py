import unittest
from pathlib import Path


HOMING_CFG = Path(__file__).resolve().parents[1] / "examples" / "easy-additions" / "homing.cfg"


class HomingConfigTests(unittest.TestCase):
    def test_unhomed_z_bootstrap_marks_only_z_homed(self):
        lines = HOMING_CFG.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(line.strip() == "[homing_override]" for line in lines), 1)
        try:
            start = next(i for i, line in enumerate(lines) if line.strip() == "[homing_override]")
        except StopIteration as exc:
            raise AssertionError("missing [homing_override] section") from exc
        end = next((i for i in range(start + 1, len(lines))
                    if lines[i].strip().startswith("[") and lines[i].strip().endswith("]")), len(lines))
        section_lines = lines[start + 1:end]
        self.assertNotEqual(section_lines, [])

        # This is a source-level contract check; it does not simulate Klipper.
        normalized = []
        for line in section_lines:
            # Keep Jinja directives, but remove formatting-only noise.
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = line.split(";", 1)[0].strip()
            if line:
                normalized.append(line)

        # Raw command equality prevents duplicate parameters from being hidden.
        set_lines = [line for line in normalized if line.startswith("SET_KINEMATIC_POSITION")]
        self.assertIn("G90", normalized)
        self.assertIn("{% if 'z' not in printer.toolhead.homed_axes %}", normalized)
        self.assertEqual(set_lines, ["SET_KINEMATIC_POSITION Z=0 SET_HOMED=Z"])
        self.assertEqual(normalized.count("SET_KINEMATIC_POSITION Z=0 SET_HOMED=Z"), 1)

        # The guard and bootstrap must remain one contiguous normalized window.
        expected = [
            "G90",
            "{% if 'z' not in printer.toolhead.homed_axes %}",
            "SET_KINEMATIC_POSITION Z=0 SET_HOMED=Z",
            "G0 Z10 F1000",
            "{% elif printer.toolhead.position[2]|float < 10 %}",
        ]
        window = tuple(expected)
        guard_index = normalized.index(expected[1])
        self.assertGreater(guard_index, 0)
        self.assertEqual(normalized[guard_index - 1:guard_index + len(expected) - 1], expected)
        self.assertTrue(any(tuple(normalized[i:i + len(window)]) == window
                            for i in range(len(normalized) - len(window) + 1)))
