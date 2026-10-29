"""Public, dependency-free toy tasks and explicit fault challenges.

Held-out checks are written only after an arm finishes. These are small local
engineering probes, not a representative coding benchmark or leaderboard.
"""

# Embedded task source strings deliberately preserve their exact bytes.
# ruff: noqa: E501

from dataclasses import dataclass


@dataclass(frozen=True)
class BenchmarkCase:
    key: str
    objective: str
    initial: str
    public: str
    heldout: str
    answer: str
    fault: str = ""
    files: tuple[tuple[str, str], ...] = ()
    targets: tuple[str, ...] = ("solution.py",)
    references: tuple[str, ...] = ()
    category: str = "algorithm"
    answer_files: tuple[tuple[str, str], ...] = ()


MODEL_CASES = (
    BenchmarkCase(
        "words",
        "Implement count_words(text): whitespace-separated Unicode tokens; empty input is zero. Preserve its one-argument API.",
        "def count_words(text):\n    return len(text.split(' '))\n",
        "from solution import count_words\nassert count_words('hello world') == 2\nassert count_words('') == 0\n",
        "from solution import count_words\nassert count_words('  one\\t二\\nthree ') == 3\nassert count_words('\\t\\n') == 0\nassert count_words('a') == 1\n",
        "def count_words(text):\n    return len(text.split())\n",
    ),
    BenchmarkCase(
        "intervals",
        "Implement merge_intervals(intervals): return sorted closed intervals merged on overlap or touching endpoints; return [] for empty input and do not mutate the input.",
        "def merge_intervals(intervals):\n    return intervals\n",
        "from solution import merge_intervals\nassert merge_intervals([[1,3],[2,4]]) == [[1,4]]\nassert merge_intervals([]) == []\n",
        "from solution import merge_intervals\nx=[[5,7],[1,3],[3,5],[9,10]]\nassert merge_intervals(x)==[[1,7],[9,10]]\nassert x==[[5,7],[1,3],[3,5],[9,10]]\nassert merge_intervals([[1,10],[2,3]])==[[1,10]]\n",
        "def merge_intervals(intervals):\n    out=[]\n    for start,end in sorted(intervals):\n        if out and start <= out[-1][1]:\n            out[-1][1]=max(out[-1][1],end)\n        else:\n            out.append([start,end])\n    return out\n",
    ),
    BenchmarkCase(
        "topology",
        "Implement topo_order(deps), a dict of node -> prerequisite nodes. Include all named prerequisites. Choose lexicographically smallest available node each time, do not mutate input, and raise ValueError on cycles.",
        "def topo_order(deps):\n    return list(deps)\n",
        "from solution import topo_order\nassert topo_order({'b':['a'],'a':[]})==['a','b']\nassert topo_order({})==[]\n",
        "from solution import topo_order\nassert topo_order({'c':['a'],'b':[]})==['a','b','c']\nx={'c':['a','b'],'a':[],'b':[]}\nassert topo_order(x)==['a','b','c']\nassert x=={'c':['a','b'],'a':[],'b':[]}\ntry:\n    topo_order({'a':['b'],'b':['a']})\nexcept ValueError:\n    pass\nelse:\n    raise AssertionError('cycle must be refused')\n",
        "def topo_order(deps):\n    pending={n:set(ds) for n,ds in deps.items()}\n    for ds in deps.values():\n        for n in ds:\n            pending.setdefault(n,set())\n    out=[]\n    while pending:\n        ready=sorted(n for n,ds in pending.items() if not ds)\n        if not ready:\n            raise ValueError('cycle')\n        n=ready[0]\n        out.append(n)\n        del pending[n]\n        for ds in pending.values():\n            ds.discard(n)\n    return out\n",
    ),
)
CONTROLLED_CASES = (
    MODEL_CASES[0],
    BenchmarkCase(
        "test_repair",
        MODEL_CASES[0].objective,
        MODEL_CASES[0].initial,
        MODEL_CASES[0].public,
        MODEL_CASES[0].heldout,
        MODEL_CASES[0].answer,
        "first_attempt_fails",
    ),
    BenchmarkCase(
        "unlocked_dependency",
        MODEL_CASES[0].objective,
        MODEL_CASES[0].initial,
        MODEL_CASES[0].public,
        MODEL_CASES[0].heldout,
        MODEL_CASES[0].answer,
        "undeclared_dependency",
    ),
    BenchmarkCase(
        "fake_lock",
        MODEL_CASES[0].objective,
        MODEL_CASES[0].initial,
        MODEL_CASES[0].public,
        MODEL_CASES[0].heldout,
        MODEL_CASES[0].answer,
        "untrusted_dependency",
    ),
)
