import std;
import rules;

int main() {
    using namespace ::policy;
    auto valid_order=[](std::size_t count,std::span<DependencyEdge const> edges,std::span<std::size_t const> order) {
        if (order.size()!=count) return false;
        std::vector<std::size_t> positions(count,count);
        for (std::size_t i=0;i<count;++i) {
            if (order[i]>=count || positions[order[i]]!=count) return false;
            positions[order[i]]=i;
        }
        for (auto edge:edges) if (positions[edge.prerequisite]>=positions[edge.consumer]) return false;
        return true;
    };
    std::vector<DependencyEdge> diamond{{0,1},{0,2},{1,3},{2,3},{0,1}};
    auto order=dependency_order(5,diamond);
    if (!order || !valid_order(5,diamond,*order)) return 1;
    if (dependency_order(0,std::array{DependencyEdge{0,0}}).error()!=DependencyError::invalid_edge ||
        dependency_order(1,std::array{DependencyEdge{0,0}}).error()!=DependencyError::cycle ||
        dependency_order(max_dependency_nodes+1,{}).error()!=DependencyError::limit) return 1;
    std::vector<DependencyEdge> too_many(max_dependency_edges+1,{0,0});
    if (dependency_order(1,too_many).error()!=DependencyError::limit) return 1;
    auto cycle=diamond; cycle.push_back({3,0});
    if (dependency_order(5,cycle).error()!=DependencyError::cycle) return 1;
    // Independent transitive closure checks all directed graphs of four nodes.
    for (unsigned mask=0;mask<(1u<<16);++mask) {
        bool reach[4][4]{};
        std::vector<DependencyEdge> edges;
        for (std::size_t i=0;i<4;++i) for (std::size_t j=0;j<4;++j)
            if (mask & (1u<<(i*4+j))) { edges.push_back({i,j}); reach[i][j]=true; }
        for (std::size_t k=0;k<4;++k) for (std::size_t i=0;i<4;++i) for (std::size_t j=0;j<4;++j)
            reach[i][j]=reach[i][j] || (reach[i][k] && reach[k][j]);
        bool cyclic=false;
        for (std::size_t i=0;i<4;++i) cyclic=cyclic || reach[i][i];
        auto result=dependency_order(4,edges);
        if (cyclic ? (result || result.error()!=DependencyError::cycle) :
                     (!result || !valid_order(4,edges,*result))) return 1;
    }
    std::vector<DependencyEdge> chain;
    for (std::size_t i=1;i<max_dependency_nodes;++i) chain.push_back({i,i-1});
    auto long_order=dependency_order(max_dependency_nodes,chain);
    if (!long_order || !valid_order(max_dependency_nodes,chain,*long_order)) return 1;
    std::cout << "dependency graph validation and ordering passed\n";
}
