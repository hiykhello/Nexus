-- xmake 3.1.2 can miss a consumer rebuild when a dependency module was
-- built separately. Include interface content fingerprints in compiler flags
-- so an ABI change invalidates every dependent target's objects and BMIs.
rule("nexus.module_tracking")
    after_load(function (target)
        local fingerprints = {}
        local dependencies = {target}
        for _, dependency in ipairs(target:orderdeps()) do table.insert(dependencies, dependency) end
        for _, dependency in ipairs(dependencies) do
            for _, file in ipairs(dependency:sourcefiles()) do
                if file:endswith(".cppm") or file:endswith(".ixx") then
                    table.insert(fingerprints, hash.sha256(file))
                end
            end
        end
        table.sort(fingerprints)
        for _, fingerprint in ipairs(fingerprints) do
            target:add("defines", "NEXUS_MODULE_DEP_" .. fingerprint)
        end
    end)
rule_end()
