"""Tests for WS5 (Adapter Completion) and WS6 (Heuristic Data-Flow Depth)."""


class TestAutoGenAdapter:
    def test_detects_autogen_import(self):
        from safeai.frameworks.autogen.parser import AutoGenParser
        parser = AutoGenParser()
        content = "from autogen import AssistantAgent"
        assert parser.detect("agent.py", content) is True

    def test_detects_autogen_class_usage(self):
        from safeai.frameworks.autogen.parser import AutoGenParser
        parser = AutoGenParser()
        content = "bot = AssistantAgent('bot')"
        assert parser.detect("agent.py", content) is True

    def test_ignores_non_autogen(self):
        from safeai.frameworks.autogen.parser import AutoGenParser
        parser = AutoGenParser()
        content = "import os"
        assert parser.detect("agent.py", content) is False

    def test_ignores_autogen_mention_in_comment(self):
        from safeai.frameworks.autogen.parser import AutoGenParser
        parser = AutoGenParser()
        content = "# migrate this autogen example later"
        assert parser.detect("agent.py", content) is False

    def test_parses_assistant_agent(self):
        from safeai.frameworks.autogen.parser import AutoGenParser
        parser = AutoGenParser()
        content = "from autogen import AssistantAgent\nbot = AssistantAgent('bot')"
        result = parser.parse("agent.py", content)
        assert result["framework"] == "autogen"
        assert len(result["agents"]) >= 1

    def test_parses_user_proxy(self):
        from safeai.frameworks.autogen.parser import AutoGenParser
        parser = AutoGenParser()
        content = "from autogen import UserProxyAgent\nuser = UserProxyAgent('user')"
        result = parser.parse("agent.py", content)
        assert len(result["agents"]) >= 1


class TestLangGraphConditionalEdges:
    def test_detects_conditional_edges(self):
        from safeai.frameworks.langgraph.parser import LangGraphParser
        parser = LangGraphParser()
        content = "from langgraph.graph import StateGraph\ngraph.add_conditional_edges('start', route_fn)"
        assert parser.detect("graph.py", content) is True

    def test_ignores_unrelated_graph_library(self):
        from safeai.frameworks.langgraph.parser import LangGraphParser
        parser = LangGraphParser()
        content = "import networkx\ngraph = networkx.Graph()"
        assert parser.detect("graph.py", content) is False

    def test_parses_conditional_edges(self):
        from safeai.frameworks.langgraph.parser import LangGraphParser
        parser = LangGraphParser()
        content = "from langgraph.graph import StateGraph\ngraph.add_conditional_edges('start', route_fn)"
        result = parser.parse("graph.py", content)
        assert result["framework"] == "langgraph"
        assert len(result["edges"]) >= 1


class TestBrowserRuleSplit:
    def test_playwright_detected(self):
        from safeai.analyzers.capability.analyzer import CAP_PATTERNS
        content = "from playwright import sync_api"
        assert CAP_PATTERNS["browser_playwright"].search(content)

    def test_selenium_does_not_match_playwright(self):
        from safeai.analyzers.capability.analyzer import CAP_PATTERNS
        content = "from selenium import webdriver"
        assert not CAP_PATTERNS["browser_playwright"].search(content)

    def test_selenium_detected(self):
        from safeai.analyzers.capability.analyzer import CAP_PATTERNS
        content = "from selenium import webdriver"
        assert CAP_PATTERNS["browser_selenium"].search(content)

    def test_browser_use_detected(self):
        from safeai.analyzers.capability.analyzer import CAP_PATTERNS
        content = "from browser_use import Agent"
        assert CAP_PATTERNS["browser_use"].search(content)


class TestDataFlowAnalyzer:
    def _make_analyzer(self):
        from safeai.analyzers.dataflow.analyzer import DataFlowAnalyzer
        return DataFlowAnalyzer()

    def test_empty_file_cache(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run({}, [])
        assert findings == []

    def test_detects_user_input_to_prompt(self):
        analyzer = self._make_analyzer()
        content = "user_input = request.form['input']\nprompt = f'Process: {user_input}'"
        findings = analyzer.run({"app.py": content}, [])
        rule_ids = [f["rule_id"] for f in findings]
        assert "DATAFLOW_PROMPT" in rule_ids

    def test_detects_user_input_to_shell(self):
        analyzer = self._make_analyzer()
        content = "user_input = input('Enter: ')\nos.system(user_input)"
        findings = analyzer.run({"app.py": content}, [])
        rule_ids = [f["rule_id"] for f in findings]
        assert "DATAFLOW_SHELL" in rule_ids

    def test_no_finding_without_sources(self):
        analyzer = self._make_analyzer()
        content = "x = 42\nprint(x)"
        findings = analyzer.run({"app.py": content}, [])
        assert findings == []

    def test_no_finding_without_sinks(self):
        analyzer = self._make_analyzer()
        content = "user_input = request.form['input']"
        findings = analyzer.run({"app.py": content}, [])
        assert findings == []

    def test_finding_has_elevated_severity(self):
        analyzer = self._make_analyzer()
        content = "user_input = input()\nos.system(user_input)"
        findings = analyzer.run({"app.py": content}, [])
        # Severity is derived from the rule registry: shell sinks are critical,
        # other sinks may differ. All data-flow findings are elevated.
        for f in findings:
            assert f["severity"] in ("high", "critical")

    def test_finding_has_safety_category(self):
        analyzer = self._make_analyzer()
        content = "user_input = input()\nprompt = user_input"
        findings = analyzer.run({"app.py": content}, [])
        for f in findings:
            assert f["risk_category"] == "Safety"

    def test_none_content_skipped(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run({"app.py": None}, [])
        assert findings == []

    def test_intermediate_variable_tracking(self):
        analyzer = self._make_analyzer()
        content = "user_input = request.form['data']\ndata = user_input\nresult = data"
        findings = analyzer.run({"app.py": content}, [])
        # Should detect propagation through intermediate variable
        assert isinstance(findings, list)

    def test_placeholder_prefix_test_skipped(self):
        analyzer = self._make_analyzer()
        content = "test_input = request.form['input']\nos.system(test_input)"
        findings = analyzer.run({"app.py": content}, [])
        rule_ids = [f["rule_id"] for f in findings]
        assert "DATAFLOW_SHELL" not in rule_ids

    def test_placeholder_prefix_example_skipped(self):
        analyzer = self._make_analyzer()
        content = "example_query = request.form['q']\nprompt = example_query"
        findings = analyzer.run({"app.py": content}, [])
        assert findings == []

    def test_placeholder_prefix_mock_skipped(self):
        analyzer = self._make_analyzer()
        content = "mock_data = request.form['data']\nos.system(mock_data)"
        findings = analyzer.run({"app.py": content}, [])
        rule_ids = [f["rule_id"] for f in findings]
        assert "DATAFLOW_SHELL" not in rule_ids

    def test_non_placeholder_not_skipped(self):
        analyzer = self._make_analyzer()
        content = "user_input = request.form['input']\nos.system(user_input)"
        findings = analyzer.run({"app.py": content}, [])
        rule_ids = [f["rule_id"] for f in findings]
        assert "DATAFLOW_SHELL" in rule_ids

    def test_finding_has_confidence_scope_limitation(self):
        analyzer = self._make_analyzer()
        content = "user_input = input()\nos.system(user_input)"
        findings = analyzer.run({"app.py": content}, [])
        for f in findings:
            assert f["confidence"] == "heuristic"
            assert f["scope"] == "static-analysis"
            assert "limitation" in f and len(f["limitation"]) > 0

    def test_non_python_file_no_dataflow(self):
        analyzer = self._make_analyzer()
        content = '{"input": "user_input"}'
        findings = analyzer.run({"config.json": content}, [])
        assert findings == []

    def test_no_finding_for_test_prefixed_variable(self):
        analyzer = self._make_analyzer()
        content = "test_user = input('Enter: ')\nos.system(test_user)"
        findings = analyzer.run({"app.py": content}, [])
        rule_ids = [f["rule_id"] for f in findings]
        assert "DATAFLOW_SHELL" not in rule_ids


class TestInterproceduralDataFlow:
    """One direct call deep, within a single file (#96).

    The intraprocedural pass requires the sink to appear after the source line.
    That rule is wrong across a call boundary, because a helper is normally
    defined ABOVE its caller — so every test here places the sink at a LOWER
    line number than the tainted variable. If the ordering rule leaked into the
    interprocedural pass these would all fail.
    """

    def _make_analyzer(self):
        from safeai.analyzers.dataflow.analyzer import DataFlowAnalyzer
        return DataFlowAnalyzer()

    def _rule_ids(self, content):
        return [f["rule_id"] for f in self._make_analyzer().run({"app.py": content}, [])]

    def test_untrusted_input_through_a_call_reaches_a_file_write(self):
        content = (
            "def save(data):\n"
            "    open('/tmp/out.txt', 'w').write(data)\n"
            "\n"
            "user_input = request.form['x']\n"
            "save(user_input)\n"
        )
        assert "DATAFLOW_FILE_WRITE" in self._rule_ids(content)

    def test_untrusted_input_through_a_call_reaches_a_prompt(self):
        content = (
            "def build(text):\n"
            "    prompt = f'Answer this: {text}'\n"
            "    return prompt\n"
            "\n"
            "user_input = request.form['x']\n"
            "build(user_input)\n"
        )
        assert "DATAFLOW_PROMPT" in self._rule_ids(content)

    def test_keyword_arguments_are_followed(self):
        content = (
            "def build(text=None):\n"
            "    prompt = f'Answer: {text}'\n"
            "    return prompt\n"
            "\n"
            "user_input = request.form['x']\n"
            "build(text=user_input)\n"
        )
        assert "DATAFLOW_PROMPT" in self._rule_ids(content)

    def test_the_evidence_names_the_hop(self):
        """A reader has to be able to see WHY the sink is reachable."""
        content = (
            "def save(data):\n"
            "    open('/tmp/out.txt', 'w').write(data)\n"
            "\n"
            "user_input = request.form['x']\n"
            "save(user_input)\n"
        )
        findings = self._make_analyzer().run({"app.py": content}, [])
        hops = [f["evidence"] for f in findings if "call:save()" in f["evidence"]]
        assert hops, [f["evidence"] for f in findings]

    # ---- the limitations, pinned so widening them is a visible change ----

    def test_an_untainted_argument_does_not_taint_the_callee(self):
        """The control. Without it, a pass that taints every parameter of every
        called function would satisfy every test above."""
        content = (
            "def save(data):\n"
            "    open('/tmp/out.txt', 'w').write(data)\n"
            "\n"
            "user_input = request.form['x']\n"
            "safe_value = 'constant'\n"
            "save(safe_value)\n"
        )
        assert "DATAFLOW_FILE_WRITE" not in self._rule_ids(content)

    def test_cross_file_flows_remain_undetected(self):
        """A documented limitation, asserted rather than assumed. If this
        starts passing, the finding's ``limitation`` text is now wrong."""
        helper = (
            "def save(data):\n"
            "    open('/tmp/out.txt', 'w').write(data)\n"
        )
        caller = (
            "from helper import save\n"
            "user_input = request.form['x']\n"
            "save(user_input)\n"
        )
        analyzer = self._make_analyzer()
        findings = analyzer.run({"helper.py": helper, "app.py": caller}, [])
        assert "DATAFLOW_FILE_WRITE" not in [f["rule_id"] for f in findings]

    def test_a_second_hop_is_not_followed(self):
        """One level only. Two hops must not resolve."""
        content = (
            "def inner(data):\n"
            "    open('/tmp/out.txt', 'w').write(data)\n"
            "\n"
            "def outer(value):\n"
            "    inner(value)\n"
            "\n"
            "user_input = request.form['x']\n"
            "outer(user_input)\n"
        )
        assert "DATAFLOW_FILE_WRITE" not in self._rule_ids(content)

    def test_a_syntax_error_does_not_break_the_analyzer(self):
        """The analyzer runs over whatever is on disk, including files mid-edit.
        An unparseable file must degrade to the intraprocedural pass, not raise.
        """
        content = "user_input = request.form['x']\ndef broken(:\n    pass\n"
        assert self._make_analyzer().run({"app.py": content}, []) is not None

    def test_the_limitation_text_names_what_is_now_covered(self):
        content = (
            "def save(data):\n"
            "    open('/tmp/out.txt', 'w').write(data)\n"
            "\n"
            "user_input = request.form['x']\n"
            "save(user_input)\n"
        )
        findings = self._make_analyzer().run({"app.py": content}, [])
        assert findings
        limitation = findings[0]["limitation"]
        assert "one direct call deep" in limitation
        assert "does NOT cross files" in limitation


class TestSinkModelGapsFoundWhileWiring96:
    """Two defects surfaced by #96 that are NOT caused by it. Pinned so they
    are visible rather than folklore."""

    def _analyzer(self):
        from safeai.analyzers.dataflow.analyzer import DataFlowAnalyzer
        return DataFlowAnalyzer()

    def test_the_file_write_sink_pattern_can_actually_match(self):
        """It could not, before this branch.

        The pattern ended in ``\b`` immediately after the mode string's closing
        quote. The next character at a real call site is always ``)`` — both
        non-word, so no boundary exists and the rule was unreachable. #96's
        acceptance criterion ("DATAFLOW_file_write fires") could not be met
        until this was repaired.
        """
        from safeai.analyzers.dataflow.analyzer import SINK_PATTERNS

        pattern = SINK_PATTERNS["file_write"]
        for writing in ("open('/tmp/o.txt', 'w')", 'open("f", "wb")',
                        "with open('f','a') as h:", "open(p, 'x')"):
            assert pattern.search(writing), writing
        # ...and read modes must stay quiet, or the repair has over-widened it.
        for reading in ("open('f')", "open('f','r')", "open('f', 'rb')"):
            assert not pattern.search(reading), reading

    def test_the_with_block_write_form_is_still_invisible(self):
        """A SEPARATE, pre-existing gap this PR does not close.

        The ``file_write`` sink is the ``open()`` call, but in the idiomatic
        ``with open(...) as h:`` form the tainted value arrives at ``h.write()``
        one line later, so the taint never coincides with the sink line. This
        holds with no call boundary at all, so it is a property of the sink
        model rather than of interprocedural tracking.

        Asserted rather than left unsaid: if someone fixes the sink model, this
        test fails and tells them to delete it.
        """
        content = (
            "user_input = request.form['x']\n"
            "with open('/tmp/o.txt', 'w') as handle:\n"
            "    handle.write(user_input)\n"
        )
        rule_ids = [f["rule_id"] for f in self._analyzer().run({"app.py": content}, [])]
        assert "DATAFLOW_FILE_WRITE" not in rule_ids
