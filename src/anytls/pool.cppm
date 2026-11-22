export module anytls.pool;
import net.connection_pool;

export namespace anytls {
    using net::PoolClock;
    using net::PoolError;
    using net::PoolOptions;
    template<class Connection> using ClientPool=net::ConnectionPool<Connection>;
}
