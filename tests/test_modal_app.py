import unittest

try:
    import modal_app
except ImportError:  # modal not installed
    modal_app = None


@unittest.skipIf(modal_app is None, "modal not installed")
class PickClaudeToken(unittest.TestCase):
    def test_picks_one_and_hides_the_rest(self):
        env = {"CLAUDE_OAUTH_TOKEN_1": "a", "CLAUDE_OAUTH_TOKEN_2": "b", "CLAUDE_OAUTH_TOKEN_3": "", "PATH": "/bin"}
        out = modal_app.pick_claude_token(env, choose=lambda pool: pool[-1])
        self.assertEqual(out, {"CLAUDE_CODE_OAUTH_TOKEN": "b", "PATH": "/bin", "CLAUDE_OAUTH_TOKEN_3": ""})

    def test_keeps_single_token_without_pool(self):
        env = {"CLAUDE_CODE_OAUTH_TOKEN": "x"}
        self.assertEqual(modal_app.pick_claude_token(env), {"CLAUDE_CODE_OAUTH_TOKEN": "x"})
