from langgraph import Graph

def node_a(state):
    return state

g = Graph()
g.add_node(node_a)

user_input = "test"
prompt = f"System: do X {user_input}"
