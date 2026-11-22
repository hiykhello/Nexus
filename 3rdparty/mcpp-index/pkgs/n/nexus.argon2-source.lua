-- Unmodified upstream reference C implementation, pinned archive.
-- Source symbols are renamed for collision-free static composition.
package = {
  spec = "1", namespace = "nexus", name = "argon2-source",
  description = "Pinned Argon2 reference C core", licenses = { "Apache-2.0" },
  repo = "https://github.com/P-H-C/phc-winner-argon2", type = "package",
  archs = { "x86_64" },
  xpm = { linux = { ["20190702-nexus.2"] = {
    url = "https://github.com/P-H-C/phc-winner-argon2/archive/62358ba2123abd17fccf2a108a301d4b52c01a7c.tar.gz",
    sha256 = "d177732879114c07a5ab7e6533e61d2c9dff204044335537c89ed16e7d3e4e2f",
  } } },
  mcpp = { language = "c++26", c_standard = "gnu11", import_std = false,
    include_dirs = { "*/include", "*/src" }, private_include_dirs = { "*/src" },
    defines = { "ARGON2_NO_THREADS", "FLAG_clear_internal_memory=nexus_snell_FLAG_clear_internal_memory", "allocate_memory=nexus_snell_allocate_memory", "argon2_ctx=nexus_snell_argon2_ctx", "argon2_encodedlen=nexus_snell_argon2_encodedlen", "argon2_error_message=nexus_snell_argon2_error_message", "argon2_hash=nexus_snell_argon2_hash", "argon2_type2string=nexus_snell_argon2_type2string", "argon2_verify=nexus_snell_argon2_verify", "argon2_verify_ctx=nexus_snell_argon2_verify_ctx", "argon2d_ctx=nexus_snell_argon2d_ctx", "argon2d_hash_encoded=nexus_snell_argon2d_hash_encoded", "argon2d_hash_raw=nexus_snell_argon2d_hash_raw", "argon2d_verify=nexus_snell_argon2d_verify", "argon2d_verify_ctx=nexus_snell_argon2d_verify_ctx", "argon2i_ctx=nexus_snell_argon2i_ctx", "argon2i_hash_encoded=nexus_snell_argon2i_hash_encoded", "argon2i_hash_raw=nexus_snell_argon2i_hash_raw", "argon2i_verify=nexus_snell_argon2i_verify", "argon2i_verify_ctx=nexus_snell_argon2i_verify_ctx", "argon2id_ctx=nexus_snell_argon2id_ctx", "argon2id_hash_encoded=nexus_snell_argon2id_hash_encoded", "argon2id_hash_raw=nexus_snell_argon2id_hash_raw", "argon2id_verify=nexus_snell_argon2id_verify", "argon2id_verify_ctx=nexus_snell_argon2id_verify_ctx", "b64len=nexus_snell_b64len", "blake2b=nexus_snell_blake2b", "blake2b_final=nexus_snell_blake2b_final", "blake2b_init=nexus_snell_blake2b_init", "blake2b_init_key=nexus_snell_blake2b_init_key", "blake2b_init_param=nexus_snell_blake2b_init_param", "blake2b_long=nexus_snell_blake2b_long", "blake2b_update=nexus_snell_blake2b_update", "clear_internal_memory=nexus_snell_clear_internal_memory", "copy_block=nexus_snell_copy_block", "decode_string=nexus_snell_decode_string", "encode_string=nexus_snell_encode_string", "fill_first_blocks=nexus_snell_fill_first_blocks", "fill_memory_blocks=nexus_snell_fill_memory_blocks", "fill_segment=nexus_snell_fill_segment", "finalize=nexus_snell_finalize", "free_memory=nexus_snell_free_memory", "index_alpha=nexus_snell_index_alpha", "init_block_value=nexus_snell_init_block_value", "initial_hash=nexus_snell_initial_hash", "initialize=nexus_snell_initialize", "numlen=nexus_snell_numlen", "secure_wipe_memory=nexus_snell_secure_wipe_memory", "validate_inputs=nexus_snell_validate_inputs", "xor_block=nexus_snell_xor_block" },
    sources = { "*/src/argon2.c", "*/src/core.c", "*/src/blake2/blake2b.c", "*/src/thread.c", "*/src/encoding.c", "*/src/ref.c" },
    targets = { ["argon2-source"] = { kind = "lib" } }, deps = {},
  },
}
