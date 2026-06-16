package graph

type NodeType string

const (
	NodeNamespace          NodeType = "Namespace"
	NodeWorkload           NodeType = "Workload"
	NodeContainer          NodeType = "Container"
	NodeService            NodeType = "Service"
	NodeIngress            NodeType = "Ingress"
	NodeServiceAccount     NodeType = "ServiceAccount"
	NodeRole               NodeType = "Role"
	NodeClusterRole        NodeType = "ClusterRole"
	NodeRoleBinding        NodeType = "RoleBinding"
	NodeClusterRoleBinding NodeType = "ClusterRoleBinding"
	NodeSecret             NodeType = "Secret"
	NodeExternalEndpoint   NodeType = "ExternalEndpoint"
)

type EdgeType string

const (
	EdgeExposes                EdgeType = "exposes"
	EdgeRunsAs                 EdgeType = "runs-as"
	EdgeBoundTo                EdgeType = "bound-to"
	EdgeCanRead                EdgeType = "can-read"
	EdgeCanWrite               EdgeType = "can-write"
	EdgeCanCreate              EdgeType = "can-create"
	EdgeMounts                 EdgeType = "mounts"
	EdgeAccessibleFromInternet EdgeType = "accessible-from-internet"
)

type Node struct {
	ID        string
	Type      NodeType
	Name      string
	Namespace string
}

type Edge struct {
	From   string
	To     string
	Type   EdgeType
	Weight int
}

type Graph struct {
	Nodes map[string]Node
	Edges []Edge
}

type Path struct {
	Nodes  []Node
	Edges  []Edge
	Weight int
}

func New() Graph {
	return Graph{
		Nodes: map[string]Node{},
		Edges: []Edge{},
	}
}

func (g *Graph) AddNode(node Node) {
	g.Nodes[node.ID] = node
}

func (g *Graph) AddEdge(edge Edge) {
	g.Edges = append(g.Edges, edge)
}
