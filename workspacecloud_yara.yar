rule WorkspaceCloud_Memory_Generic
{
    meta:
        description = "Stage-aware in-memory detection for the WorkspaceCloud bootstrap and final Rust implant"
        author = "Simone Marinari"
        date = "2026-09-27"
        scope = "memory"
        confidence = "medium-high"
        reference_bootstrap_sha256 = "421b77fec6b3c3b0b80a1caa092623167438170ac61ed87c43343bfaaed2925d"
        reference_implant_sha256 = "4e8b69023192576fad2c5bba654fa99eefe51fba0067bab61c34e3ed4c918356"
        note = "Intended for live-process, VAD, or process-dump scanning; do not deploy as a filesystem rule"
    strings:
        /* Bootstrap network artefacts. */
        $bootstrap_net_ua  = "WorkspaceCloud-SDK" ascii wide
        $bootstrap_net_uri = "/api/v2/sdk/init" ascii wide
        /* Stable labels and build/capability artefacts from the final implant. */
        $implant_core_key = "CONFIG_KEY_PART_0" ascii wide
        $implant_cap_pipe = "\\\\.\\pipe\\MSI_DU_" ascii wide
        $implant_core_pdb = "implant.pdb" ascii wide
        $implant_core_cfg = "CONFIG_BLOB" ascii wide
    condition:
        /* The two stages may live in different processes and at different times. */
        all of ($bootstrap_net_*)
        or
        3 of ($implant_*)
}