#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 07-13-2026
    
    Note:
    07-13-2026: Added SuspendBitlockerForSVN switch (checked/enabled by default). Immediately
                before a new or already-pending Stage 3/4 SVN operation, the
                script suspends every encrypted OS/fixed-data BitLocker
                volume for two reboots. Combined Stage 3+4, Stage 3-only, and
                Stage 4-only paths share the same safety boundary. A suspension
                failure blocks a new irreversible trigger, and the affected
                volumes/results are reported in a separate card section and log.
                A shared pre-mode/post-repair manifest pass also applies this
                protection in Passive/Audit mode when Stage 3/4 bits were pushed
                by Windows Update, policy, or another tool; audit remains non-enforcing.
              - Replaced the runtime-compiled native UEFI attribute reader with
                the Attributes property already returned by Windows' inbox
                Get-SecureBootUEFI cmdlet during the existing db read. This
                removes custom native interop and token-privilege manipulation
                while preserving the original RUNTIME_ACCESS (0x04),
                TIME_BASED_AUTHENTICATED_WRITE_ACCESS (0x20), KEK authority,
                $dbIsOsWritable, Event 1795, PK, state, and SVN logic unchanged.
              - Bumped the SVN baseline version from 7.0 to 8.0 following the
                release of version 9.0 in June, 2026.
    05-26-2026: Post-compliance variable-cert refresh no longer reports as a
                regression. Compliance requires only the two db certs
                Windows UEFI CA 2023 + Microsoft UEFI CA 2023 (plus KEK 2023);
                Microsoft Option ROM UEFI CA 2023 is variable per make/model/oem.
                Field reports showed devices that reached Event 1808 then received
                a fresh 1801 once Windows Update began serving the Option ROM cert.
                The latest state event flipped to 1801 and the card downgraded
                to Pending ("stuck on 1801") despite the required certs being
                present and the device having booted compliant.
                Fix: a new $variableCertRefresh precompute (required certs +
                KEK present, Option ROM the only db cert missing, prior 1808 in
                history, latest event 1801) and a new "State 3-pre" branch ahead
                of the Compliant state that holds Compliant with an "(variable
                cert update pending)" note instead of regressing. The Option ROM
                row in the certificate inventory now renders blue/pending rather
                than a red X in this case. KEK-present is required so genuine
                1795/1803 OEM blockers are not masked.
                Also: the HP BIOS section no longer prints a row for toggles the
                firmware does not expose. Absence is the indicator. Only exposed
                settings are listed. The not-exposed count remains summarized
                in the header parenthesis.
    05-20-2026: HP BIOS remediation now gates strictly on the Enable opt-in
                action. Added $script:IsEnableAction (-like 'Enable*', same
                truncation-proof pattern as $script:IsAuditAction) and changed
                Step 2.18 to write firmware toggles only when that flag is set.
                Previously the write fired on any non-audit run, which meant
                'Remove opt-in for SecureBoot management' also flipped the HP
                BIOS toggles on - contradictory intent and a needless BIOS
                write. Audit and Remove opt-in are now both no-ops for the HP
                BIOS branch; only Enable opt-in performs the remediation.
                Audit-mode guard hardening (root cause of an HP BitLocker
                recovery report). Ninja's dropdown variable resolution requires
                exact values, the "Audit" instead of "Audit SecureBoot management
                status" in the [ValidateSet] had was being checked in the HP logic
                with the full string, and falling through the filter, routing the
                script into the non-audit branch of Step 2.18 and writing HP BIOS
                toggles on an intended read-only audit run, which triggered BitLocker
                recovery on the next reboot.
                Fix: begin{} now normalizes any loose input strings up front via a
                wildcard switch (Audit* / Enable* / Remove*) back to the
                canonical ValidateSet string, and logs the rewrite when it
                happens so operators can see the upstream resolution bug.
                A pre-computed $script:IsAuditAction flag (-like 'Audit*') is
                exposed for downstream filtering. Step 2.18 now consults it
                instead of the raw string comparison.
    05-15-2026: HP BIOS handling reshaped around field testing.
                - Get-HpBiosCa2023Settings now splits results into NonCompliant
                  (Present-but-wrong, eligible for SetBIOSSetting) and NotExposed
                  (firmware doesn't surface the toggle - SetBIOSSetting returns
                  rc=4). Many HP firmwares only expose 'Enable MS UEFI CA key',
                  which on its own is enough to reach Event 1808 - the three
                  CA 2023 toggles being missing is firmware-normal, not a fault.
                  AllCompliant now ignores NotExposed.
                - Set-HpBiosCa2023Settings no longer attempts writes against
                  NotExposed settings (caller passes NonCompliant only) and
                  decides BitLocker suspend internally based on whether any
                  write actually returned rc=0 (ChangesMade > 0). Previous
                  logic gated the suspend on Test-HpStuckEventPattern, which
                  produced two bugs: Device 2 flipped 'Enable MS UEFI CA key'
                  No -> Yes without stuck history, suspend skipped, BitLocker
                  recovery on next reboot; Device 3 had a stale 1796 in the log
                  while at 1808, suspend fired on every re-run despite no
                  writes happening. Tying suspend to actual writes-made matches
                  what BitLocker measures (PCR drift), not log history.
                - Test-HpStuckEventPattern gained a freshness gate: if the
                  latest state event is 1808, the device has moved past the
                  stuck loop and the filter returns $false regardless of any
                  stale 1796/1800/1801 in the log (Device 3 above).
                - Build-HpBiosSection: NotExposed rows render in info-blue
                  ("not exposed by firmware") instead of red question-marks;
                  the AllCompliant header carries a small parenthetical note
                  about not-exposed counts; the "Why this is flagged" paragraph
                  is split into <b>headed</b> sentences and wrapped in a
                  max-width:767px block so it stops overflowing the card; the
                  remediation result handles the new BitLockerSkipped case
                  ("no BIOS settings were changed in this run"); the manual
                  <details> fallback is now only surfaced when the auto-write
                  was skipped (audit mode) or the interface was unavailable,
                  reducing noise on runs where the script already did the work.
    05-12-2026: HP BIOS remediation decoupled from the stuck-state filter. The four
                CA 2023 BIOS toggles are now written via HP_BIOSSettingInterface on
                any non-audit run when they report non-compliant - opt-in always
                fixes the toggles regardless of whether the 1796 / 1800 / 1801
                fingerprint is in the current event window. Test-HpStuckEventPattern
                now controls only (a) whether manage-bde -RebootCount 3 fires
                (unnecessary on already-1808 devices) and (b) card wording:
                red Action Required (stuck) vs amber latent risk
                (1808 but BIOS still Disabled) vs amber filter-not-matched
                (BIOS write applies anyway). Set-HpBiosCa2023Settings now takes
                -CertStatus / -AvailableUpdatesBits and calls the filter internally
                to drive the manage-bde decision - no caller-side switch.
                Build-HpBiosSection always renders the remediation result block
                when a write was attempted, adds a "Why this is flagged"
                significance paragraph on the non-stuck branches, and surfaces a
                manual <details> fallback whenever the auto-write was skipped
                (audit mode) or HP_BIOSSettingInterface was unavailable.
    05-11-2026: HP BIOS configuration test for stuck devices. Run in Opt-In mode to
                apply misconfigured HP BIOS settings (if needed).
                This also includes a new HPBIOS card section for visual clarity.
    05-07-2026: Addressed parsing errors for emojies in some environments. Now fully
                supports the Windows Powershell 5.1 without any catches.
    04-30-2026: PK-blocks-KEK now overrides the "all mitigations applied -> Compliant
                  (pending 1808)" path. State 5b-pre-blocker case added at the top of
                  the resolution switch: when has2023InDb + 1799 + 1037 + 1042 all
                  fire AND $pkBlockingKek is true (Event 1795 firing + KEK 2K CA
                  2023 missing on a legitimate OEM PK), the device routes to Action
                  Required with the existing 1795 OEM-BIOS narrative instead of
                  green-checking. Previously the AllMitigationsApplied path treated
                  mitigation events as sufficient and never consulted $pkBlockingKek,
                  producing a misleading "Compliant (pending 1808)" headline on
                  Lenovo / OEM devices where the PK actively rejects KEK 2023 writes
                  79+ times. $pkBlockingKek computation hoisted to before the state-
                  resolution switch so the case can consult it.
                - $svnRebootPending boot-time-vs-1042 check now also floor-gated
                  (was previously unconditional). On a device that just had 1042
                  fire but already meets the documented compliance floor, the
                  "Pending SVN Reboot" overlay was firing for an absorption that
                  doesn't move the floor. Now suppressed when $svnStatus.IsCompliant.
                  Same gate applied to the mit4-triggered-without-1042 fallback.
    04-29-2026: Get-SignatureDataSVN now reads the major/minor uint16 fields as
                  little-endian, matching garlin's April 2026 SVN_Order.ps1 update.
                  Previous big-endian read happened to produce correct values on
                  every SVN currently shipped (major < 256, minor == 0) because the
                  high byte of major sat at hex 40-41 == 0x00 and hex 36-37 (real
                  minor low byte) was also 0x00. The fix lands before Microsoft
                  pushes any SVN with a non-zero minor or a major >= 256, where the
                  bug would otherwise silently mis-render the value.
                  (https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates/commit/d356e1645d14440f1113dbd31a78ff374c19e1ef)
                - SVN section now surfaces all five SVNs explicitly:
                  the cmdlet-conventional trio (Firmware / Boot Manager / Staged) and
                  the always-raw additional components (CdBoot / WdsMgr). Result hash
                  exposes CdBootSVN and WdsMgrSVN sourced from the same Get-DbxComponentSVNs
                  pass that feeds FirmwareSVN, so the values are guaranteed consistent
                  with the per-component log line.
                  Previously CdBoot/WdsMgr were only visible in the per-component log
                  line; now they sit alongside Firmware/BootMgr/Staged on the card so
                  operators can verify all three boot components at a glance (especially
                  useful when only BootMgr moves and the others lag).
                - SvnUpdatePending and RebootPending now floor-gated so a higher-numbered
                  staged SVN does not generate "Pending SVN Reboot" overlays or
                  "SVN update pending" callouts when firmware is already at or above
                  the documented compliance floor. Previously a Stage-4-complete device
                  (firmware 7.0, staged 8.0) reported "Compliant (Pending SVN Reboot)"
                  with "SVN update pending (DBXUpdateSVN.bin 8.0 not yet in DBX)" at the
                  same time the DBX validation summary said "Staged DBX fully applied"
                  because the SVN entry was correctly marked superseded by floor but
                  the pending-reboot signals were still firing on raw firmware<staged.
                  Two gates applied: $svnUpdatePending in Get-SecureBootSVNStatus (now
                  $false when floorMet) and the $svnRebootPending check in the post-DBX
                  classification block (now skips entirely when $svnStatus.IsCompliant).
                  A higher staged SVN is a future version Microsoft has shipped ahead of
                  any actual enforcement. Bump the floor when live to report compliance.
                - SVN compliance is now authoritative from $script:SVN_COMPLIANCE_FLOORS,
                  not the Get-SecureBootSVN cmdlet's ComplianceStatus string. The cmdlet
                  computes its narrative from its own FirmwareSVN reading, which the
                  PowerShell#27058 bug silently under-reports - on a Stage-4-complete
                  device (raw firmware SVN 7.0) the cmdlet returns FirmwareSVN=2.0 and
                  ComplianceStatus="Not compliant - Firmware does not match boot manager".
                  Trusting that string flipped the card to "Not compliant" on a clearly
                  compliant device. Now: floor met -> Compliant ("Firmware SVN $X >=
                  floor $Y") regardless of cmdlet narrative; floor missed -> fall back
                  to the cmdlet's wording (still useful color in the actual non-compliant
                  case). Same authoritative rule applies on raw-only devices.
                - Get-WindowsUpdateSVN now strips the ASN.1 authenticode wrapper
                  (bytes 40..41 == 0x30 0x82) from DBXUpdateSVN.bin before parsing.
                  Without the strip the EFI_SIGNATURE_LIST walker silently returned
                  nothing and the card showed "Staged SVN: N/A" on devices that
                  clearly had a staged update file. Compare-DbxAgainstStagedBins
                  was already stripping correctly via Get-StrippedDbxBinBytes;
                  Get-WindowsUpdateSVN is now consistent. Also picks max-by-version
                  across all BootMgr-prefixed entries.
                - Added per-component SVN compliance floor ($script:SVN_COMPLIANCE_FLOORS,
                  default 7.0 for BootMgr / CdBoot / WdsMgr) consulted by the staged-vs-
                  firmware classifier in Compare-DbxAgainstStagedBins. A SVN-keyed entry
                  is now marked 'superseded' (compliant) when firmware SVN >= floor,
                  even if the staged DBXUpdateSVN.bin contains a newer SVN value. Fixes
                  the false "SVN Update Not Applied (BootMgr)" callout that fired on
                  Stage 4-compliant devices the moment Microsoft bumped the staged
                  file's SVN past the active enforcement target (e.g. 7.0 -> 8.0).
                  Distinguishes DBXUpdate2024.bin (BootMgr SVN 2.0 + 2011 CA revocation)
                  from DBXUpdateSVN.bin (BootMgr SVN -> rollout-target). Bump the floor
                  per documented Microsoft milestones.
                - Consolidated raw-DBX SVN parsing behind a single Get-DbxComponentSVNs
                  helper so Get-DbxBootMgrSVN, Compare-DbxAgainstStagedBins, and
                  Get-SecureBootSVNStatus all route through one canonical max-by-version
                  parser. Values diff cleanly against raw SVNswhen verifying the
                  PowerShell#27058 workaround on a device.
                - Get-SecureBootSVNStatus now logs all three boot-component SVNs
                  (BootMgr / CdBoot / WdsMgr) on every invocation regardless of
                  cmdlet availability or DBX state ('absent' on pre-rollout devices).
                - Unified the SVN status contract: same hash shape (FirmwareSVN /
                  BootManagerSVN / StagedSVN / ComplianceStatus / etc.) returns on
                  every stage. FirmwareSVN and StagedSVN are now always sourced from
                  raw DBX bytes (canonical, bug-free) - the cmdlet is consulted only
                  for the on-disk-only fields BootManagerSVN and BootManagerPath plus
                  the authoritative ComplianceStatus string, with N/A fallbacks when
                  KB5077241 is not present. Card / log / console output dropped their
                  Source-based forks in favor of one identical Firmware / Boot Manager
                  / Staged presentation, and the Stage 3+ reboot-pending check no
                  longer gates on Source since both operands are always available.
    04-24-2026: Event 1803 (PK-signed KEK 2023 not available via WU) is now recognized
                  as a state event and routed to Action Required. Previously 1803 was
                  not in $stateEventIds, so a device with 1803 as its most recent
                  event was not recognized as an actionable branch.
                - Added an explicit $has2023InDb + $has1803 branch describing 1803:
                  the PK is valid, the OEM has simply not published a
                  PK-signed KEK 2023 update to Microsoft for WU to serve. This is
                  NOT a firmware/PK authority issue (that is 1795). While a BIOS
                  update COULD be the fix, OEM publication through WU is also supported.
                  PK row stays green for 1803 (as it is a valid OEM PK).
                - Updated the two pre-existing 1803 branches with the same reframing
                  and corrected their event-row label to "Event 1803" instead of
                  "Event 1801". Event-row label in the generic ActionRequired case
                  is now dynamic (1801 or 1803 as applicable).
    04-23-2026: Pre-rollout DBX validation notice now fires correctly when a non-SVN
                  hash is also missing alongside the three SVN-component entries.
                  Previous gate required $missingComponents.Count == $MissingCount,
                  which flunked whenever a single unrelated dbxupdate.bin hash was
                  outstanding (common on Stage 1/2 devices). New gate only checks
                  that every SVN-component miss has no firmware SVN yet; the non-SVN
                  hash surfaces under its own per-file row as before. Per-file
                  "missing: BootMgr (staged X, raw firmware absent)" sub-rows are
                  suppressed when pre-rollout so the breakdown does not contradict
                  the reassurance notice above it.
                - Fixed a known bug with the Get-SecureBootSVN cmdlet, which in its
                current state, is almost entirely useless for firmware SVN readout:
                https://github.com/PowerShell/PowerShell/issues/27058
                  Same defect existed in Get-DbxBootMgrSVN and the firmwareSvnByGuid
                  build (both used a lex-sort that returned the DBX-order-last entry
                  instead of the numeric max). Replaced with explicit max-by-[version]
                  parsing across all three SVN-keyed GUIDs (BootMgr / CdBoot / WdsMgr).
                - Added cmdlet cross-check: when Get-SecureBootSVN returns a different
                  FirmwareSVN than the raw-DBX max.
                - Three-way SVN miss classification added: PendingUpdate (firmware at
                  prior SVN, reboot will apply) vs SvnNotApplied (firmware refused to
                  absorb after reboot - OEM BIOS update may be required) vs
                  PartialCommit (residual asymmetric rejection). Cross-references
                  Win32_OperatingSystem.LastBootUpTime against the latest Event
                  1034/1042 timestamp to tell "pre-reboot" from "stuck-after-reboot".
    04-22-2026: Major QoL update with the following improvements:
                  - Added PK (Platform Key) parsing; PK CN and trust indicator now shown
                    in the Certificates section.
                  - Added VMware / VirtualBox hypervisor detection (via SignatureOwner GUID
                    a3d5e95b-0a8f-4753-8735-445afb708f62 for VMware, Subject regex for
                    VirtualBox). New "Virtualized" card state routes VM guests out of the
                    Action Required / Pending ladder.
                  - Added PKDefault / KEKDefault / dbxDefault parsing alongside existing
                    dbDefault. When defaults are missing, a "Factory Defaults" section
                    (PK+KEK enrollment, KEK-only).
                  - Added Compare-DbxAgainstStagedBins: parses every dbx*.bin file
                    staged by Windows servicing under
                    C:\Windows\System32\SecureBootUpdates\ and reports which
                    signatures the firmware has absorbed. Answers the actionable
                    question "did the Secure-Boot-Update scheduled task commit what
                    servicing staged?". SVN-aware: revocations already superseded
                    by the live BootMgr / CdBoot / WdsMgr SVN, are reported as superseded
                    instead of missing. Runs whenever Secure Boot is Enabled and DBX bytes
                    are available.
                  - Added Get-KekUpdateAvailability: downloads kek_update_map.json and
                    reports whether a vendor-signed KEK 2023 update is available for the
                    current PK thumbprint. Runs only when KEK 2023 missing + Event 1795/1803.
                  - Added Test-BootMediaPca2023 + -DeepBootMediaScan switch. Always scans
                    removable/optical volumes for PCA-2011-signed bootX.efi files. Card
                    section surfaces only when outdated media is present.
                    Plaintext SecureBootStatus field flags the count when detected.
                  - Added Get-UefiCertSubjects consolidation helper (wraps
                    Get-UefiDatabaseCerts with CN/hypervisor/trust post-processing plus
                    an optional -MicrosoftOnly filter.
                  - Stage suffix (e.g. " | Stage 3+4") now appended to the plaintext
                    SecureBootStatus field for all non-Compliant/Disabled/NotApplicable/
                    Virtualized states so the single-line field is self-describing.
                  - Fixed: $enforceMissingOptIn is now re-evaluated with fresh
                    Check-OptInStatus result after Step 2.3 so that when
                    SecureBootAction='Enable opt-in...' transitions a device from
                    not-opted-in to opted-in during the same run, the card and
                    plaintext field no longer show stale "WU opt-in not enabled" warnings.
                  - PK security branch, providing insight and remediation information for
                    CVE-2024-8105, also known as PKFail.
                  - Imporoved clarity, reporting details, and accuracy.
    04-13-2026: Small, cosmetic wording fix for the event section when there is an
                updated status, but no SecureBoot events in the event log.
    04-03-2026: Fixed an enforcement branch (stage 2) event bug incorrectly
                missing an event check, resulting in a weird card output.
                Fixed update section visibility in this same case.
                Allows stage branch to correctly show all cases accurately
                Major bug fix for preliminary certs and improper ORing of updatebits,
                which were overriding any pending bits, breaking any pending updates
                from going through.
                Enforcing stage 3+4 caused a security trigger to break if they
                were already pending a reboot, which resulted in reverting the
                stage 3-4 updatebits/progress for them to apply.
                Added AS1 signature strip in Parse-UefiSignatureDatabase.
                Fixed stateEventIds to help finalization undestanding & Accuracy.
                Fixed State 5b-pre branch logic to properly report state.
                Addressed Final stage pending accuracy based on events and SVN #
    04-01-2026: Addressed a small, out of place HTML cosmetic bug, with the
                "What is this?" a tag link not processing through the build-*
                pipeline. Examples how to handle additional title info dynamically.
                CSS modification so a tags do not have underlining for HTML cards.
                SecureBootAction no longer writes AvailableUpdates.
                SVN Enforcement sub-section always visible for better insight.
                Addressed inconsist reporting & accuracies between Passive & Enforce.
                Cosmetic clarity and fine-tuning UI states/instances.
                Improved WU Opt-In reporting to show only when needed.
                Addressed a bug with Build-UpdatesSection that left persitent pending-
                updates after all stages have been applied (causing confusion).
                Has2023InDb now specifically checks for Windows UEFI CA 2023.
                Identifies other 2023 certs in a new supplemental step, sets bitmask,
                checks for added cert data after, warning and continuing on.
                  During my testing of this, it worked flawlessly, setting the
                  Update bits, triggering the task, firing events the events.
                  No reboots were needed in my testing when applying
                Removed Get-ShortCertName, caused too much confusion.
                Addressed a missing firmware and event check for 1795.
    03-31-2026: Stage 3+4 prerequisite gate (Test-SvnStagePrerequisites): prevents
                mitigations 3 (0x80) and 4 (0x200) from executing unless Stage 1+2
                are VERIFIED complete. Two-signal validation per stage:
                  Stage 1: cert physically in db (ground truth) AND 0x40 bit consumed
                  Stage 2: Event 1799/1808 confirmed AND 0x100 bit consumed
                Reboot detection: Event 1800 or unconfirmed Mitigation 2 blocks gate.
                Used by both Invoke-SvnEnforcement (active gate) and passive safety check.
                SVN Enforcement Repair (Repair-SvnEnforcement): detects prematurely
                triggered Stage 3+4 bits in AvailableUpdates and clears them before
                the next reboot processes them. Checks reversibility: if Events 1037
                (2011 CA revoked) or 1042 (SVN applied) have already fired, DBX is
                modified and cannot be undone from Windows - provides OEM-specific
                BIOS key reset guidance. Runs in both Enforce and Passive modes.
                Post-enforcement safety check: after Invoke-SvnEnforcement, if
                mitigations 3+4 were Blocked but their bits exist in the manifest
                (from this run or a prior run), Repair-SvnEnforcement clears them.
                Passive mode safety check: even in audit-only mode, scans for
                premature Stage 3+4 bits and clears them to prevent damage on reboot.
                Invoke-SvnEnforcement gate refactored: replaced simple Event 1800
                check with full Test-SvnStagePrerequisites call for Mitigation 3+4
                (ground truth + manifest + reboot), with detailed gate logging.
    03-30-2026: SVN Enforcement engine (Invoke-SvnEnforcement): applies KB5025885 /
                CVE-2023-24932 enterprise deployment guidance mitigations 1-4 when $EnforceSvnCompliance = 'Enforce SVN', only
                when applicable (stages 1-2 are fully complete with no pending updates, etc).
                Each mitigation writes AvailableUpdates bitmask + triggers Secure-Boot-Update
                task: Mitigation 1 (0x40, DB cert), Mitigation 2 (0x100, Boot manager),
                Mitigation 3 (0x80, revoke PCA 2011 in DBX), Mitigation 4 (0x200, apply SVN).
                Gate logic: Mits 3+4 block on Event 1800 (pending cert reboot) and check
                pre-existing completion via DBX presence / event 1037/1042 before applying.
                Enforcement results include per-mitigation BlockedReason for card display.
                Passive enforcement mode: detects "previously enforced" when events 1037/1042
                predate Microsoft's June 26 2026 enforcement date.
                SVN reboot-pending detection refactored from unreliable DBX SVN byte comparison
                to boot-time cross-reference (Win32_OperatingSystem.LastBootUpTime vs event
                timestamps). Cmdlet path (FirmwareSVN < StagedSVN) preserved as supplemental.
                Cert inventory now uses three-state icons: green (confirmed via 1799/1808),
                blue (pending - manifest bit set but OS hasn't confirmed), red (absent and
                not pending). Cross-references AvailableUpdates manifest bits per-cert.
                PCA 2011 revocation line: ban icon color reflects state (green=complete,
                blue=pending reboot, yellow=unknown). Inline "(revoked in dbx - pending
                reboot)" replaces separate indented line.
                Updates section simplified: "No Updates Pending (all applied)" when fully
                applied, otherwise "Pending (header note)" with bullet list. Registry hex
                value moved to Write-Log only (not displayed on card).
                Update manifest enrichment: gate widened to include event-confirmed mitigations
                (1037/1042) even without registry opt-in. Fresh AvailableUpdates re-read +
                event-based OR-ing of 0x0080/0x0200 ensures manifest accuracy.
                Detail text now appends SVN summary: "Reboot required to complete SVN firmware
                updates" / "No action required" / "SVN updates pending - awaiting Microsoft
                rollout (June 2026 - 2027)". Replaces static "No action required" when SVN
                needs action. Fixed stale 1801 detail text that incorrectly claimed "OS update
                triggered via reg key" in Audit mode.
                Rollout Tier: formats multi-value comma-separated confidence as numbered list,
                strips "3P " prefix, single char entries present "Under Observation - More Data Needed".
                Fixed Get-DbxSignatureData offset bug: was reading byte 0 instead of byte 32
                for SVN signature data extraction (critical bug).
                Major refactoring: extracted 15+ helper functions to eliminate ~550 lines of
                duplicated HTML/plain-text card rendering. Build-* functions accept -Format
                'Html'|'Local' parameter - single source of truth for every card section
                (Certificates, Servicing, Updates, SVN Compliance, Enforcement, Rollout Tier,
                Update Task, Opt-In, Event Log). Supporting helpers: Format-CardIcon (unified
                FA/emoji renderer), Test-HasSecureBootEvent, Get-LatestSecureBootEvent,
                Get-ShortCertName, Test-SvnRebootPending, Get-OemGuide (merged KeyReset +
                BIOSUpdate into one parameterized function).
                Major Local card re-implementation & formatting to match Ninja 1:1.
    03-27-2026: SVN (Security Version Number) compliance, full implementation.
                Uses Get-SecureBootSVN cmdlet (February 2025 KB5077241+) when available,
                with raw DBX byte parsing fallback for all devices (pre-KB5077241).
                Raw DBX extracts BootMgr SVN from EFI_CERT_SHA256_GUID signature entries
                using hex offsets (major at 36-39, minor at 40-43).
                Compares live DBX SVN against DBXUpdateSVN.bin staging file
                (System32\SecureBootUpdates) to detect pending SVN updates.
                SVN progression: 0.0 (none) → 2.0 (PCA 2011 revoked) → 7.0 (full).
                Three-way display: Compliant / Pending (2011 not yet revoked) /
                Non-compliant. "Not compliant" with FirmwareSVN 0.0 is expected
                pre-Stage 3 when PCA 2011 hasn't been revoked yet.
                Rollout timeline:
                  Stage 1 (May 2024)  : 2023 certs added to db via Windows Update
                  Stage 2 (Feb 2025)  : 2023 boot manager deployed, SVN cmdlet added
                  Stage 3 (est. 2026) : PCA 2011 revoked in dbx, SVN enforcement begins
                  Stage 4 (est. 2027) : Full enforcement - 2011 certs removed from db
                Added Get-SecureBootUEFI -Decoded parameter support (KB5077241+) for
                richer cert parsing without raw byte fallback.
                SVN Compliance card section now appears after Pending Updates.
                Sources: garlin's SecureBoot-CA-2023-Updates scripts,
                    (https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates)
                  microsoft/secureboot_objects (GitHub)
    03-24-2026: Manifest cross-referencing has been added, now checks each manifest bit
                against actual cert presence:
                  0x0040 -> checks if Windows UEFI CA 2023 is in $dbCertsFound
                  0x0800 -> checks if Microsoft Option ROM UEFI CA 2023 is in $dbCertsFound
                  0x1000 -> checks if Microsoft UEFI CA 2023 is in $dbCertsFound
                  0x0004/0x4004 -> checks $has2023InKek
                  0x0100 -> checks if Event 1799 has occurred
                Addresses incorerct assumptions about Update Completion/Manifest.
                dbDefault now tracks which certs are found.
                Three-way logic for missing KEK (both State 4 with 1801 and State 5b without events):
                  dbIsOsWritable -> Action Optional (KEK present, WU will handle it)
                  has1803 -> Action Required (OEM blocker, key reset or firmware update genuinely needed)
                  No 1803 -> Pending, opt-in can push KEK; tells you if opted in or not
                Added WindowsUEFICA2023Capable check and 2011 CA Revocation Cross-Check;
                  Source: https://github.com/cjee21/Check-UEFISecureBootVariables
    03-24-2026: Removed "Pending (1799)" as a distinct state - Event 1799 now falls
                through to the general Pending state. UEFICA2023Status='Updated' is
                the ground truth; age-based 1799 guessing was unnecessary.
                Added 1799->1808 informational note: when 1799 is latest and servicing
                confirms Updated but 1808 is absent from the log, annotates card/console
                that 1808 is expected on the next scheduled task cycle (runs at startup
                + every 12h). No nudge or wait - just an informational annotation.
                Fixed reboot correlation to show latest reboot (closest to 1799).
                Fixed cert name: 'Microsoft Corporation UEFI CA 2023' -> 'Microsoft
                UEFI CA 2023' (matching actual certificate CN).
                Fixed BucketConfidenceLevel extraction: restricted to Event 1801/1808
                only (1800 messages contain garbage metadata), added UpdateType: prefix
                cleanup, null out empty confidence values.
                Added Secure Boot servicing registry reads (UEFICA2023Status, Error,
                ErrorEvent, CanAttemptUpdateAfter from Servicing + DeviceAttributes).
                UEFICA2023Status='Updated' now serves as supplemental compliance signal
                alongside Event 1808. Added Get-Win32ErrorMessage for error code decoding.
                Added Get-AvailableUpdatesMeaning bitmask decoder (0x0004 KEK, 0x0040
                Windows UEFI CA, 0x0100 boot manager, 0x0800 Option ROM CA, 0x1000
                Microsoft UEFI CA, 0x4000 conditional on 2011 trust). Detects unknown bits.
                Enhanced Check-OptInStatus to also read AvailableUpdatesPolicy (GPO/MDM
                persistent trigger) and HighConfidenceOptOut (auto-deployment opt-out).
                Enhanced Get-CertUpdateEventStatus to extract BucketId,
                BucketConfidenceLevel, and SkipReason (KI_<number>) from event messages.
                Card now shows: Certificate Inventory (all 4 certs), Servicing status
                with error details, decoded AvailableUpdates bitmask, Rollout Tier
                (confidence level + skip reason), and enhanced Opt-In with policy/opt-out.
                Sources: MS KB5084567, Get-SecureBootCertInfo.ps1 (HorizonSecured),
                Detect-SecureBootCertUpdateStatus.ps1 (Microsoft Official).
    03-23-2026: Major event log expansion, now queries all 19 Secure Boot TPM-WMI event
                IDs per MS KB5016061, including firmware/error events (1795 firmware
                rejected write, 1796 unexpected error, 1797 prerequisite failure,
                1798 boot mgr not signed, 1802 blocked by known limitation, 1803
                PK-signed KEK not found). Color-coded event log summary in the status
                card with aggregated occurrence counts and timestamps.
                Fixed State 5 bug: "Action Optional" was shown for all has2023InDbDefault
                cases regardless of $dbIsOsWritable, now correctly gates on the flag.
                Fixed inconsistent $statusKey ('Pending' vs card showing 'Action Optional').
                Fixed trigger logic: Step 2.5 no longer re-triggers when Event 1800
                (reboot required) or 1799 (boot manager installed) is the latest state.
                These are in-progress states that need a reboot.
                Added distinct state handling for Event 1800 ("Pending Cert Reboot") and
                Event 1799 ("Pending" with age-based reboot detection) in the state
                switch, replacing the generic "Pending" catch-all for these events.
    03-19-2026: Added Check-OptInStatus function, always checks telemetry and opt-in
                registry keys (AllowTelemetry, MaxTelemetryAllowed,
                MicrosoftUpdateManagedOptIn, AvailableUpdates) and surfaces result
                in the status card as "Opt-In Status" line.
                Added Trigger-SecureBootTask call after Enable opt-in sets registry keys.
                Increased UEFI variable buffer from 4 KB to 64 KB for large OEM db vars.
                Updated error hint text to include common Win32 error codes (122, 1314).
    03-18-2026: Added "Action Optional" state when UEFI db is OS-writable, downgrades
                Action Required to Action Optional (Windows will push cert automatically).
                Applied to both State 4 (Event 1801) and State 5 (Pending/no events) when
                cert is missing from db or only in dbDefault.
                Added "Audit Secure Boot management status" action, read-only check of
                telemetry keys (AllowTelemetry, MaxTelemetryAllowed), and opt-in keys
                (MicrosoftUpdateManagedOptIn, AvailableUpdates) without making changes..
    03-05-2026: Added passive UEFI variable attributes check for 'db'. This indicates the OS is Allowed to
                write directly to the UEFI cert db, which windows should then eventually update on its own, without
                a need to update the BIOS/Firmware individually (insightful for systems with no BIOS update).
                Integrated into core logic: Passive check always runs if Secure Boot Enabled.
    03-02-2026: Added the abillity to optionally store the status outputs under local storage.
                This outputs 2 files and bypasses the Ninja custom field storage logic.
    02-26-2026: Implemented additional checks for reliable Secure Boot detection.
                Fixed handling of UEFI variable Bytes as array; added parsing of
                db/dbx certificate contents with detailed logging.
                Added check for 'Windows UEFI CA 2023' in db and dbDefault via string match.
                Simplified cert logging to subjects only. Removed non-essential logs.
                Updated ActionRequired state to differentiate between firmware update
                and key reset based on dbDefault presence.
                Added automation to set AvailableUpdates registry key (0x5944) if 2023 cert
                in db but still 1801 (no 1808); updates fields to reflect triggered state.
                After setting reg key, wait 1 min and check for 1799. Update pending messages
                based on presence of 1799 (await 1808 ~15min) or not (await 1799 ~5min).
                Added BitLocker recommendation for key reset. Added OEM BIOS check and links
                for key reset guides.
                Added explicit trigger of Secure-Boot-Update scheduled task after setting reg key.
                Also utilize WinCsFlags.exe /apply if available for more precise config apply.
    02-24-2026: Initial creation. Reports Secure Boot state and 2023 certificate
                update status (Event 1808/1801) via NinjaRMM custom fields.
#>

<#
.SYNOPSIS
    Audits Secure Boot certificate rotation (Microsoft 2023 certs) across PK, KEK,
    db, dbx, and the full set of factory default variables (PKDefault / KEKDefault /
    dbDefault / dbxDefault), and reports actionable status via NinjaRMM custom fields,
    or LocalHTMLCard. Flags PKFail / CVE-2024-8105 (publicly-leaked AMI Test PK) as
    a dedicated PK Untrusted state. Optionally enables or removes the Windows Update
    opt-in for Secure Boot management. Also scans attached removable/optical media
    for outdated PCA-2011-signed boot loaders, and validates the firmware DBX against
    every dbx*.bin staging file Windows has shipped. Reporting matched / missing /
    superseded signatures plus a three-way SVN miss classification
    (PendingUpdate / SvnNotApplied / PartialCommit) whenever Secure Boot is Enabled.

.DESCRIPTION
    Checks whether the machine supports UEFI Secure Boot, whether it is enabled,
    and (if enabled) performs a comprehensive audit:
      
      Certificate databases:
        - Parses PK (platform root of trust), KEK (key exchange keys), db (allowed
          signatures), dbx (revocations), and the four factory defaults (PKDefault /
          KEKDefault / dbDefault / dbxDefault) for X509 certificates.
        - Checks for all four 2023 certificates Microsoft is rotating to:
            db:  Windows UEFI CA 2023, Microsoft UEFI CA 2023,
                 Microsoft Option ROM UEFI CA 2023
            KEK: Microsoft Corporation KEK 2K CA 2023
        - KEK is the trust authority that authorizes writes to db. If the 2023 KEK
          authority cert is missing, Windows Update cannot sign the payload needed
          to push new certs into db - even if UEFI attributes allow runtime writes.
        - PK trust check: flags placeholder/example PKs (Subject match "DO NOT" or
          "Example") as untrusted.
        - Factory defaults check: when defaults are partially or fully missing,
          surfaces a "Factory Defaults" card row with manual-recovery guidance.
      
      Virtualization awareness:
        - Detects VMware guests via SignatureOwner GUID
          a3d5e95b-0a8f-4753-8735-445afb708f62 in PK with an empty certificate payload.
        - Detects VirtualBox via a Subject regex match on "VirtualBox".
        - Virtualized guests route to a dedicated "Virtualized" card state instead
          of the physical-host Action Required / Pending ladder.
      
      Local-file validation:
        - DBX validation (any time Secure Boot is Enabled): parses every dbx*.bin
          file staged by Windows servicing under
          C:\Windows\System32\SecureBootUpdates\ and reports which signatures the
          firmware has absorbed (matched / missing / superseded-by-SVN). Surfaces
          a per-staged-file breakdown when anything is outstanding. No network.
        - SVN-component miss classification: when any of the three SVN-keyed DBX
          entries (BootMgr / CdBoot / WdsMgr) is outstanding, the card narrates
          which of four states the device is in:
            * Pre-rollout         - firmware has no SVN entries at all; reassuring
                                    notice (expected pre-enforcement state, awaiting
                                    Microsoft rollout June 2026 - 2027).
            * PendingUpdate       - firmware at a prior SVN; reboot will absorb.
            * SvnNotApplied (red) - firmware booted after the DBX write and still
                                    refused the SVN; OEM BIOS/firmware update may
                                    be required. Detected via LastBootUpTime >
                                    max(Event 1034, Event 1042) timestamps.
            * PartialCommit       - asymmetric rejection (some SVN components
                                    absorbed, others refused).

      Network-sourced validation (opt-in, bounded):
        - KEK update availability (KEK 2023 missing + Event 1795/1803 only): downloads
          https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/KEK/kek_update_map.json
          and reports whether a vendor-signed KEK update is available for the current
          PK thumbprint. Network failures are logged but never break the card.
      
      Boot media scan (runs every execution):
        - Enumerates removable + CD-ROM volumes and inspects EFI\boot\bootX.efi files
          for PCA-2011 issuer signatures. Emits a card row only when outdated media
          is detected. Deep WIM scanning is opt-in via -DeepBootMediaScan.
        - Reference: https://support.microsoft.com/en-us/topic/updating-windows-bootable-media-to-use-the-pca2023-signed-boot-manager-d4064779-0e4e-43ac-b2ce-24f434fcfa0f
      
      UEFI variable attributes (passive, read-only):
        - Reuses the Attributes property returned by Windows' inbox
          Get-SecureBootUEFI cmdlet during the existing db read. No custom native
          interop or direct token-privilege manipulation is used.
        - Checks for RUNTIME_ACCESS (0x04) and TIME_BASED_AUTHENTICATED_WRITE_ACCESS (0x20).
        - Combined with the KEK 2023 check, determines whether Windows Update can
          effectively write to the BIOS cert db from the OS.
      
      Event log (TPM-WMI - 19 event IDs per MS KB5016061):
        - State events: 1808 (compliant), 1801 (action required), 1800 (reboot
          required), 1799 (boot manager installed)
        - Deployment events: 1043 (KEK updated), 1044 (Option ROM CA added),
          1045 (Microsoft UEFI CA added), 1036 (DB applied), 1034 (DBX applied),
          1037 (2011 CA revoked), 1042 (Boot Manager SVN applied)
        - Blocker events: 1032 (BitLocker conflict), 1033 (vulnerable bootloader)
        - Firmware/error events: 1795 (firmware rejected write), 1796 (unexpected
          error), 1797 (Windows UEFI CA 2023 cert not in DB), 1798 (boot mgr not signed),
          1802 (blocked by known limitation), 1803 (PK-signed KEK not found)
        - Aggregated summary with occurrence counts displayed in the status card.
      
      Servicing registry (HKLM:\...\SecureBoot\Servicing):
        - UEFICA2023Status: definitive compliance state ("Updated" = done)
        - UEFICA2023Error / UEFICA2023ErrorEvent: last error code + event ID
        - CanAttemptUpdateAfter (DeviceAttributes): next allowed attempt time
        - OEM manufacturer, model, firmware version/date
      
      AvailableUpdates bitmask decoding:
        - Decodes each bit into pending update descriptions
        - Reads both AvailableUpdates (volatile) and AvailableUpdatesPolicy (GPO/MDM persistent)
        - Detects HighConfidenceOptOut (auto-deployment opt-out flag)
      
      Rollout metadata (from event messages):
        - BucketId: Microsoft's device grouping hash
        - BucketConfidenceLevel: "High Confidence" (auto-eligible) vs "Action Required" (manual)
        - SkipReason: KI_<number> known firmware issue IDs
      
      Scheduled task:
        - Checks whether \Microsoft\Windows\PI\Secure-Boot-Update exists.
      
      Automation (when 2023 cert is in db but OS hasn't acknowledged via 1808):
        - Sets AvailableUpdates + MicrosoftUpdateManagedOptIn (0x5944)
        - Runs WinCsFlags.exe /apply if available
        - Triggers the Secure-Boot-Update scheduled task
        - Waits and checks for post-trigger event progression (1799 -> 1808)
    
    Outputs an HTML status card and a searchable plain-text summary to NinjaRMM
    custom fields (or local files via -SaveStatusLocal).
    
    The ten possible output states are:
      1. Not Applicable         - Non-UEFI or unsupported hardware
      2. Disabled               - UEFI capable but Secure Boot is off
      2b. Virtualized           - VMware / VirtualBox guest; Secure Boot cert rotation is
                                  hypervisor-managed (not guest-OS controlled)
      2c. PK Untrusted          - Platform Key is a publicly-known placeholder (PKFail /
                                  CVE-2024-8105 AMI Test PK, or a generic "DO NOT" / "Example"
                                  cert). Chain of trust is broken; a dedicated red "PK Security
                                  Alert" card section surfaces a three-tier fix ladder
                                  (OEM BIOS update -> CERT/CC PKFail script -> BitLocker
                                  suspend-first). Overrides Compliant / Pending / Action
                                  Required (structural cert presence is moot when any party
                                  can sign KEK/db/dbx updates with the leaked private key).
      3. Compliant              - Secure Boot on, Event 1808 or UEFICA2023Status='Updated'
                                  confirmed (BIOS certs updated)
      4. Action Required        - 2023 certs missing and Windows cannot write to the BIOS db
                                  (UEFI attributes or KEK authority missing); OEM firmware
                                  update or manual key reset required
      5. Action Optional        - 2023 certs missing (or in dbDefault only), but the UEFI db
                                  is OS-writable (attributes + KEK both present); Windows
                                  Update will push the cert automatically, or a manual BIOS
                                  update / key reset can expedite
      6. Pending Cert Reboot    - Event 1800 detected; reboot required to continue the update
      7. Pending                - 2023 cert in db or dbDefault but rotation not yet complete;
                                  OS update triggered where applicable
      8. Pending (Trigger)      - OS-side update triggered; monitoring for event progression,
                                  with reboot detection if stalled
    
    SVN sub-state overlays (can decorate any of the above when Secure Boot is Enabled):
      - (Pending SVN Update)     amber - firmware at a prior SVN, 1-2 components missing
                                 the next increment; reboot will absorb.
      - (SVN Update Not Applied) red   - firmware booted after the DBX write and still
                                 refused the SVN; OEM BIOS/firmware update may be required.
      - (Pending SVN Reboot)     amber - all three SVN components still missing and
                                 firmware has not booted past the DBX write yet.

.PARAMETER StatusCardFieldName
    NinjaRMM WYSIWYG custom field name for the HTML status card.
    Defaults to "SecureBootCertStatusCard" or env:secureBootStatusCardField.

.PARAMETER PlainTextFieldName
    NinjaRMM text custom field name for the plain-text summary.
    Defaults to "SecureBootCertStatus" or env:secureBootPlainTextField.

.PARAMETER SaveStatusLocal
    If specified, saves the plain-text status to a local text file and the HTML card
    to a local HTML file, in addition to any NinjaRMM field updates. Useful for
    non-NinjaRMM environments.

.PARAMETER SecureBootAction
    Optional action to take in addition to the certificate audit (which always runs).
    ValidateSet: "Enable opt-in for SecureBoot management",
                 "Remove opt-in for SecureBoot management",
                 "Audit SecureBoot management status"
      
      - Enable opt-in for SecureBoot management
            Sets required telemetry to minimum (AllowTelemetry=1,
            MaxTelemetryAllowed=1, per-user ShowedToastAtLevel=1), then sets
            MicrosoftUpdateManagedOptIn=0x5944 and AvailableUpdates=0x5944 to
            opt-in and trigger Secure Boot cert updates via Windows Update.
            If 1808 is already present (compliant), the script still follows
            through but notes that enablement was not strictly necessary.
      
      - Remove opt-in for SecureBoot management
            Removes telemetry enforcement keys (AllowTelemetry,
            MaxTelemetryAllowed) and removes MicrosoftUpdateManagedOptIn to
            opt out of Secure Boot management via Windows Update. Does NOT
            remove AvailableUpdates (already-triggered updates should complete).
      
      - Audit SecureBoot management status (default)
            Read-only check of the current opt-in and telemetry configuration.
            Reports the state of AllowTelemetry, MaxTelemetryAllowed,
            MicrosoftUpdateManagedOptIn, and AvailableUpdates registry keys
            without making any changes. No registry writes or task triggers.
            NOTE: Windows will NOT update CA2023 certificates without opt-in.
            To enable automatic deployment, set action to "Enable opt-in".

.PARAMETER EnforceSvnCompliance
      - Enforce SVN
          Follows through and applies (when aplicable & safe to do so) the SVN
          compliance steps from Microsoft KB5025885.
          NOTE: If you use BitLocker, make sure that your BitLocker recovery key
          has been backed-up. You can run the following command from an Administrator
          command prompt and note the 48-digit numerical password:
            manage-bde -protectors -get %systemdrive%
          
          Check out my Bitlocker Management & Status scripts at:
            https://github.com/SunshineSam/Scripts/tree/main/NinjaRMM/Windows/Bitlocker%20Management
            (compund condition for pending svn reboot output could work here)
          
      - Passive
          Does not enforce the SVN compliance, pending the Microsoft enforced dates
          of June 2026 for Step 3 & sometime in 2027 for the final step.
          For enterprise & environments, it is reccommended to enforce SVN for
          security purposes. Test 

.PARAMETER SuspendBitlockerForSVN
    Controls automatic BitLocker suspension immediately before irreversible SVN
    Stage 3 and/or Stage 4 processing. Switch/checkbox; default: $true
    (or env:suspendBitlockerForSVN when supplied by NinjaRMM).
    
    When enabled, every encrypted OperatingSystem and FixedData volume
    reported by Get-BitLockerVolume is suspended with RebootCount 2. This applies
    to combined Stage 3+4, Stage 3-only, Stage 4-only, and already-pending Stage
    3/4 manifest bits regardless of whether enforcement is Active or Passive/Audit.
    Volumes and failures are reported in the status card/log.

.PARAMETER IncludeDefaultHive
    Switch: Include the Default user profile template (C:\Users\Default) when applying
    per-user telemetry keys. Only effective when running as SYSTEM. Default: $false.

.PARAMETER DeepBootMediaScan
    Switch: Expands the boot-media scan (Test-BootMediaPca2023) to inspect WIM images
    inside removable / optical recovery media, rather than the expected location
    \EFI\boot\boot*.efi files. Useful when a USB install stick still carries a
    2011-signed bootmgr inside sources\boot.wim or sources\install.{wim,esd,swm}.
    Such media will fail to boot once PCA 2011 is revoked in DBX. Disabled by
    default because WIM mounting is slow and requires DISM / Get-WindowsImage.
    Ninja Script Variable: deepBootMediaScan (Checkbox). Default: $false.
#>

[CmdletBinding()]
param(
    # Ninja custom field names          Ninja Variable Resolution                                             Fallback
    [string]$StatusCardFieldName = $(if ($env:secureBootStatusCardField)  { $env:secureBootStatusCardField }  else { "SecureBootCertStatusCard" }), # Optional Ninja Script Variable; String
    [string]$PlainTextFieldName  = $(if ($env:secureBootPlainTextField)   { $env:secureBootPlainTextField }   else { "SecureBootCertStatus" }),     # Optional Ninja Script Variable; String
    
    # Other options                 Ninja Variable Resolution                                             Fallback
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $true }), # Ninja Script Variable; Checkbox
    [switch]$SaveStatusLocal = $(if ($env:saveStatusLocal) { [Convert]::ToBoolean($env:saveStatusLocal) } else { $false }), # Ninja Script Variable; Checkbox
    
    # Secure Boot opt-in action     Ninja Variable Resolution                                             Fallback
    [ValidateSet('Enable opt-in for SecureBoot management','Remove opt-in for SecureBoot management','Audit SecureBoot management status')]
    [string]$SecureBootAction = $(if ($env:securebootAction) { $env:securebootAction } else { 'Audit SecureBoot management status' }), # Optional Ninja Script Variable; Drop-down
    [switch]$IncludeDefaultHive = $(if ($env:includeDefaultHive) { [Convert]::ToBoolean($env:includeDefaultHive) } else { $true }),    # Ninja Script Variable; Checkbox
    
    # SVN enforcement mode          Ninja Variable Resolution                                             Fallback
    # "Enforce SVN" = actively apply all 4 mitigations (DB cert, boot manager, 2011 revocation, SVN update)
    # "Passive" = audit only; report current stage; wait for Microsoft's scheduled enforcement (Step 3, June 2026 - Step 4, 2027)
    [ValidateSet('Enforce SVN','Passive')]
    [string]$EnforceSvnCompliance = $(if ($env:enforceSvnCompliance) { $env:enforceSvnCompliance } else { 'Passive' }), # Optional Ninja Script Variable; Drop-down
    
    # BitLocker safety for irreversible SVN stages (Stage 3/4 only)
    # Checked/enabled suspends all encrypted OS/fixed-data volumes for two reboots
    [switch]$SuspendBitlockerForSVN = $(if ($env:suspendBitlockerForSVN) { [Convert]::ToBoolean($env:suspendBitlockerForSVN) } else { $true }), # Optional Ninja Script Variable; Checkbox
    
    # Boot media deep scan: enumerate WIM images inside USB/recovery media for 2011-signed bootmgr
    # Off by default (surface-level EFI file check is fast; WIM scanning requires DISM and is slow)
    [switch]$DeepBootMediaScan = $(if ($env:deepBootMediaScan) { [Convert]::ToBoolean($env:deepBootMediaScan) } else { $false }),
    
    # Card customization options
    [string]$CardTitle              = "Secure Boot",        # Default title
    [string]$CardIcon               = "fas fa-shield",      # Default icon (Ninja uses font awesome)
    [string]$CardBackgroundGradient = "Default",            # Gradient not supported with NinjaRMM. 'Default' omits the style.
    [string]$CardBorderRadius       = "10px",               # Default border radius
    [string]$CardSeparationMargin   = "0 8px"               # Default distance between cards
)

# =========================================
# BEGIN Block: Initialization & Functions
# =========================================
begin {
    # Immediate check if running with administrator privileges
    $isAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "`nAdministrator privileges required"
        exit 1
    }
    Write-Host "`nRunning as Administrator"
    
    #######################
    # SecureBootAction normalization
    #######################
    # Defends against a Ninja variable-resolution filtering where the expected 
    # dropdown value is not provided, passting throught input filters
    # (e.g. "Audit" instead of "Audit SecureBoot management status")
    # The [ValidateSet] on the param block validates the input value. 
    # Normalize to the canonical ValidateSet string up front so every
    # downstream comparison sees a known string. Logs the rewrite when it
    # happens so operators can spot the upstream resolution bug.
    if ($SecureBootAction) {
        $canonicalAction = switch -Wildcard ($SecureBootAction.Trim()) {
            'Audit*'  { 'Audit SecureBoot management status' ; break }
            'Enable*' { 'Enable opt-in for SecureBoot management' ; break }
            'Remove*' { 'Remove opt-in for SecureBoot management' ; break }
            default   { $SecureBootAction }
        }
        if ($canonicalAction -ne $SecureBootAction) {
            Write-Host "[INFO] SecureBootAction normalized: '$SecureBootAction' -> '$canonicalAction' (Ninja variable resolution has an indirect dropdown value)"
            $SecureBootAction = $canonicalAction
        }
    }
    # Pre-compute the action guards once so downstream callers cannot
    # accidentally re-introduce the same truncated-string bug. Any check that
    # needs "is this an audit-mode run?" should consult $script:IsAuditAction;
    # anything that performs a write-style remediation (e.g. the HP BIOS
    # toggle fix) should gate on $script:IsEnableAction so it only ever fires
    # under the Enable opt-in action - never under Audit or Remove opt-in.
    $script:IsAuditAction  = ($SecureBootAction -like 'Audit*')
    $script:IsEnableAction = ($SecureBootAction -like 'Enable*')
    
    #######################
    # Emoji table
    #######################
    # Build emoji glyphs from Unicode code points so the script source stays pure ASCII (BOM-free).
    # Avoids emojis with the default ANSI codepage in PS 5.1.
    # [char]::ConvertFromUtf32 handles BMP and supplementary (surrogate-pair) code points alike.
    $script:Emoji = @{
        Check            = [char]::ConvertFromUtf32(0x2705)                                         # check mark button
        Times            = [char]::ConvertFromUtf32(0x274C)                                         # cross mark
        Warning          = [char]::ConvertFromUtf32(0x26A0)  + [char]::ConvertFromUtf32(0xFE0F)     # warning sign + VS16
        Info             = [char]::ConvertFromUtf32(0x2139)  + [char]::ConvertFromUtf32(0xFE0F)     # information + VS16
        Sync             = [char]::ConvertFromUtf32(0x1F504)                                        # counterclockwise arrows
        Ban              = [char]::ConvertFromUtf32(0x1F6AB)                                        # prohibited
        Clock            = [char]::ConvertFromUtf32(0x23F3)                                         # hourglass with flowing sand
        Eye              = [char]::ConvertFromUtf32(0x1F441) + [char]::ConvertFromUtf32(0xFE0F)     # eye + VS16
        Building         = [char]::ConvertFromUtf32(0x1F3E2)                                        # office building
        Question         = [char]::ConvertFromUtf32(0x2753)                                         # red question mark
        QuestionWhite    = [char]::ConvertFromUtf32(0x2754)                                         # white question mark
        QuestionSmall    = [char]::ConvertFromUtf32(0xFE56)                                         # small question mark
        ExclamationWhite = [char]::ConvertFromUtf32(0x2755)                                         # white exclamation mark
        Circle           = [char]::ConvertFromUtf32(0x26AA)                                         # white circle
        Cog              = [char]::ConvertFromUtf32(0x2699)  + [char]::ConvertFromUtf32(0xFE0F)     # gear + VS16
        Calendar         = [char]::ConvertFromUtf32(0x1F4C5)                                        # calendar
        Search           = [char]::ConvertFromUtf32(0x1F50D)                                        # magnifying glass
        Link             = [char]::ConvertFromUtf32(0x1F517)                                        # link
    }
    
    #######################
    # Helper Functions
    #######################
    
    # Helper function: Define logging function for consistent output and optional file logging
    # Log file path and header state are cached to avoid per-call overhead
    $script:LogFilePath     = $null
    $script:LogHeaderWritten = $false
    
    function Write-Log {
        param (
            [string]$Level,
            [string]$Message
        )
        
        # Output the log message to the console
        Write-Host "[$Level] $Message"
        
        # Save the log message to a file on the device if enabled
        if ($SaveLogToDevice) {
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $logMessage = "[$timestamp] [$Level] $Message"
            
            # Initialize log file path once
            if ($null -eq $script:LogFilePath) {
                $systemDrive = $env:SystemDrive
                if (-not $systemDrive) { $systemDrive = 'C:' }
                $logDir = "$systemDrive\Logs\SecureBoot"
                if (-not (Test-Path $logDir)) {
                    try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch {}
                }
                $script:LogFilePath = Join-Path $logDir "SecureBootStatus.log"
            }
            
            # Write daily header once per session
            if (-not $script:LogHeaderWritten) {
                $today = Get-Date -Format 'yyyy-MM-dd'
                $header = "=== $today ==="
                try {
                    # Use StreamWriter with FileShare.ReadWrite to avoid locking issues
                    $sw = [System.IO.StreamWriter]::new($script:LogFilePath, $true, [System.Text.Encoding]::UTF8)
                    $sw.WriteLine("`r`n$header")
                    $sw.Close()
                }
                catch { }
                $script:LogHeaderWritten = $true
            }
            
            # Append log line with shared access
            try {
                $fs = [System.IO.FileStream]::new($script:LogFilePath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
                $sw = [System.IO.StreamWriter]::new($fs)
                $sw.WriteLine($logMessage)
                $sw.Close()
                $fs.Close()
            }
            catch { }
        }
    }
    
    # Helper function: Generate a standalone HTML document for local viewing (self-contained CSS)
    function Get-LocalHtmlDocument {
        param (
            [string]$Title,
            [PSCustomObject]$Data,
            [string]$AccentColor = '#26A644'
        )
        $sectionsHtml = [System.Text.StringBuilder]::new()
        foreach ($item in $Data.PSObject.Properties) {
            $sectionName = $item.Name
            $content = $item.Value
            [void]$sectionsHtml.Append(@"
            <div class="section">
                <div class="section-label">$sectionName</div>
                <div class="section-content">$content</div>
            </div>
"@)
        }
        return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$([System.Net.WebUtility]::HtmlEncode($Title))</title>
<style>
  :root {
    --accent: $AccentColor;
    --bg: #f5f6fa;
    --card-bg: #ffffff;
    --text: #272727;
    --muted: #6b7280;
    --border: #e5e7eb;
    --link: #447dcd;
    --alert-bg: #FDECEA;
    --alert-text: #272727;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #131313;
      --card-bg: #272727;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --border: #4a4a4a;
      --link: #447dcd;
      --alert-bg: #3a1518;
      --alert-text: #e5e7eb;
    }
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 24px;
    line-height: 1.5;
  }
  .card {
    max-width: 620px;
    margin: 0 auto;
    background: var(--card-bg);
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08), 0 4px 16px rgba(0,0,0,.04);
    overflow: hidden;
  }
  .card-header {
    background: var(--accent);
    color: #fff;
    padding: 16px 20px;
    font-size: 18px;
    font-weight: 600;
    letter-spacing: 0.3px;
  }
  .card-body {
    padding: 4px 0;
  }
  .section {
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
  }
  .section:last-child {
    border-bottom: none;
  }
  .section-label {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--muted);
    margin-bottom: 4px;
  }
  .section-content {
    font-size: 14px;
    word-break: break-word;
  }
  .footer {
    text-align: center;
    padding: 10px 20px 14px;
    font-size: 11px;
    color: var(--muted);
  }
  a { color: var(--link); text-decoration-line: none; }
</style>
</head>
<body>
<div class="card">
  <div class="card-header">$([System.Net.WebUtility]::HtmlEncode($Title))</div>
  <div class="card-body">
$($sectionsHtml.ToString())
  </div>
  <div class="footer">Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>
</div>
</body>
</html>
"@
    }
    
    # Helper function: Create an info card with structured data and icon color
    function Get-NinjaOneInfoCard($Title, $Data, [string]$Icon, [string]$TitleLink, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor = "#000000") {
        [System.Collections.Generic.List[String]]$ItemsHTML = @()
        foreach ($Item in $Data.PSObject.Properties) {
            $ItemsHTML.add('<p ><b >' + $Item.Name + '</b><br />' + $Item.Value + '</p>')
        }
        return Get-NinjaOneCard -Title $Title -Body ($ItemsHTML -join '') -Icon $Icon -TitleLink $TitleLink -BackgroundGradient $BackgroundGradient -BorderRadius $BorderRadius -IconColor $IconColor -SeparationMargin $CardSeparationMargin
    }
    
    # Helper function: Generate the HTML card with icon color support
    function Get-NinjaOneCard($Title, $Body, [string]$Icon, [string]$TitleLink, [string]$Classes, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor, [string]$SeparationMargin) {
        [System.Collections.Generic.List[String]]$OutputHTML = @()
        $style = "background: $BackgroundGradient; border-radius: $BorderRadius; margin: $SeparationMargin;"
        $OutputHTML.add('<div class="card flex-grow-1' + $(if ($classes) { ' ' + $classes }) + '" style="' + $style + '">')
        if ($Title) {
            $iconHtml = if ($Icon) { '<i class="' + $Icon + '" style="color: ' + $IconColor + ';"></i> ' } else { '' }
            $OutputHTML.add('<div class="card-title-box"><div class="card-title" >' + $iconHtml + $Title + '</div>')
            if ($TitleLink) {
                $OutputHTML.add('<div class="card-link-box"><a href="' + $TitleLink + '" target="_blank" class="card-link" ><i class="fas fa-arrow-up-right-from-square" style="color: #337ab7;"></i></a></div>')
            }
            $OutputHTML.add('</div>')
        }
        $OutputHTML.add('<div class="card-body" >')
        $OutputHTML.add('<p class="card-text" >' + $Body + '</p>')
        $OutputHTML.add('</div></div>')
        return $OutputHTML -join ''
    }
    
    # Helper function: Write a value to a NinjaRMM text custom field
    # Suppresses verbose/information streams and falls back to positional params if named params fail
    function Invoke-NinjaPropertySet {
        param(
            [string]$FieldName,
            [string]$Value
        )
        $NinjaPropertyCommand = 'Ninja-Property-Set'
        if (-not (Get-Command $NinjaPropertyCommand -ErrorAction SilentlyContinue)) {
            Write-Log "WARNING" "'$NinjaPropertyCommand' not found; cannot update field '$FieldName'."
            return
        }
        $oldInfoPref    = $InformationPreference
        $oldVerbosePref = $VerbosePreference
        try {
            $InformationPreference = 'SilentlyContinue'
            $VerbosePreference     = 'SilentlyContinue'
            try {
                Ninja-Property-Set -Name $FieldName -Value $Value | Out-Null
            }
            catch {
                Ninja-Property-Set $FieldName $Value | Out-Null
            }
        }
        finally {
            $InformationPreference = $oldInfoPref
            $VerbosePreference     = $oldVerbosePref
        }
    }
    
    # Helper function: Write HTML to a NinjaRMM WYSIWYG custom field via piped input
    function Invoke-NinjaPropertySetPiped {
        param(
            [string]$FieldName,
            [string]$Html
        )
        $NinjaPipedCommand = 'Ninja-Property-Set-Piped'
        if (-not (Get-Command $NinjaPipedCommand -ErrorAction SilentlyContinue)) {
            Write-Log "WARNING" "'$NinjaPipedCommand' not found; cannot update WYSIWYG field '$FieldName'."
            return
        }
        $oldInfoPref    = $InformationPreference
        $oldVerbosePref = $VerbosePreference
        try {
            $InformationPreference = 'SilentlyContinue'
            $VerbosePreference     = 'SilentlyContinue'
            $Html | Ninja-Property-Set-Piped -Name $FieldName
        }
        finally {
            $InformationPreference = $oldInfoPref
            $VerbosePreference     = $oldVerbosePref
        }
    }
    
    # Helper function: Test if a specific Secure Boot event ID exists in the event log
    # Replaces repeated pattern: @($certStatus.AllEvents | Where-Object { $_.Id -eq XXXX }).Count -gt 0
    function Test-HasSecureBootEvent {
        param (
            [object]$CertStatus,
            [int]$EventId
        )
        return ($null -ne $CertStatus -and $null -ne $CertStatus.AllEvents -and
                @($CertStatus.AllEvents | Where-Object { $_.Id -eq $EventId }).Count -gt 0)
    }
    
    # Helper function: Get the most recent occurrence of a specific Secure Boot event ID
    # Returns the event object or $null
    function Get-LatestSecureBootEvent {
        param (
            [object]$CertStatus,
            [int]$EventId
        )
        if ($null -eq $CertStatus -or $null -eq $CertStatus.AllEvents) { return $null }
        return $CertStatus.AllEvents | Where-Object { $_.Id -eq $EventId } | Sort-Object Time -Descending | Select-Object -First 1
    }
    
    # Helper function: Test if SVN reboot is pending (revocation or SVN update awaiting reboot)
    # Replaces repeated: ($null -ne $svnStatus -and ($svnStatus.RebootPending -or $svnStatus.RevocationAppliedPendingReboot))
    function Test-SvnRebootPending {
        param ([object]$SvnStatus)
        return ($null -ne $SvnStatus -and ($SvnStatus.RebootPending -or $SvnStatus.RevocationAppliedPendingReboot))
    }
    
    # Helper function: Get OEM guide URL by type (KeyReset or BIOSUpdate)
    # Consolidates Get-OemKeyResetGuide and Get-OemBIOSUpdateGuide
    function Get-OemGuide {
        param (
            [ValidateSet('KeyReset', 'BIOSUpdate')]
            [string]$GuideType
        )
        $urls = @{
            Dell      = @{ KeyReset = 'https://www.dell.com/support/kbdoc/en-us/000368610/how-to-update-secure-boot-active-database-from-bios'
                           BIOSUpdate = 'https://www.dell.com/support/kbdoc/en-us/000124211/dell-bios-updates' }
            HP        = @{ KeyReset = 'https://support.hp.com/lv-en/document/ish_13070353-13070429-16'
                           BIOSUpdate = 'https://support.hp.com/us-en/document/ish_4129273-2331498-16' }
            Lenovo    = @{ KeyReset = 'https://pubs.lenovo.com/uefi_iot/secure_boot_config'
                           BIOSUpdate = 'https://support.lenovo.com/us/en/solutions/ht500008' }
            ASUS      = @{ KeyReset = 'https://www.asus.com/us/support/faq/1050047/'
                           BIOSUpdate = 'https://www.asus.com/us/support/faq/1008276/' }
            Microsoft = @{ KeyReset = 'https://support.microsoft.com/en-us/surface/surface-secure-boot-certificates-532abf3b-bafe-420f-b615-bf174105549e'
                           BIOSUpdate = 'https://support.microsoft.com/en-us/surface/download-drivers-and-firmware-for-surface-09bb2e09-2a4b-cb69-0951-078a7739e120' }
        }
        try {
            $biosInfo = Get-CimInstance -ClassName Win32_BIOS
            $manufacturer = $biosInfo.Manufacturer
            Write-Log "INFO" "BIOS Manufacturer: $manufacturer"
            foreach ($oem in $urls.Keys) {
                if ($manufacturer -match $(if ($oem -eq 'HP') { 'HP|Hewlett-Packard' } else { $oem })) {
                    return $urls[$oem][$GuideType]
                }
            }
            Write-Log "INFO" "No matching $GuideType guide for manufacturer: $manufacturer"
            return $null
        }
        catch {
            Write-Log "WARNING" "Failed to get BIOS manufacturer: $($_.Exception.Message)"
            return $null
        }
    }
    
    # ---------------------------------------------------------------------------
    # HP-specific BIOS check (CA 2023 interface settings)
    # ---------------------------------------------------------------------------
    # Background: HP shipped many laptop/desktop models with the 4 BIOS CA 2023
    # toggles defaulted Disabled / "No". After the Enable Opt-in stage of this
    # script runs, those devices entered repeated BitLocker recovery and the
    # Boot Manager 2023 transition repeatedly stalled. Event signature when
    # stuck: 1796 + 1800 + 1801 firing on repeat, AvailableUpdates pinned at
    # 17664 (0x4500). The HP fix is to flip the 4 BIOS settings via
    # HP_BIOSSettingInterface and suspend BitLocker for 3 reboots so the cert
    # rotation can complete without recovery prompts.
    #
    # Expected enabled state (working HP devices):
    #   Windows UEFI CA 2023              = Enable
    #   Microsoft Option ROM UEFI CA 2023 = Enable
    #   Microsoft UEFI CA 2023            = Enable
    #   Enable MS UEFI CA key             = Yes
    # ---------------------------------------------------------------------------
    $script:HpExpectedBiosSettings = [ordered]@{
        'Windows UEFI CA 2023'              = 'Enable'
        'Microsoft Option ROM UEFI CA 2023' = 'Enable'
        'Microsoft UEFI CA 2023'            = 'Enable'
        'Enable MS UEFI CA key'             = 'Yes'
    }
    
    # Helper function: Read the four HP BIOS CA 2023 settings via HP_BIOSSetting WMI.
    # Returns a result object regardless of WMI availability so callers can
    # branch on .Available without try/catch.
    #   NonCompliant = settings that are Present-but-wrong (eligible for write)
    #   NotExposed   = settings the firmware doesn't expose (skip write; SetBIOSSetting
    #                  would return rc=4. Field testing shows some HP devices do not expose the 
    #                  three CA 2023 toggles are commonly not exposed while 'Enable MS UEFI CA key'
    #                  alone is sufficient for the cert rotation to succeed.
    function Get-HpBiosCa2023Settings {
        $result = [pscustomobject]@{
            Available    = $false
            Settings     = [ordered]@{}
            AllCompliant = $false
            NonCompliant = @()
            NotExposed   = @()
            Error        = $null
        }
        $hpSettings = $null
        try {
            $hpSettings = Get-CimInstance -Namespace 'root\HP\InstrumentedBIOS' -ClassName 'HP_BIOSSetting' -ErrorAction Stop
        }
        catch {
            $result.Error = $_.Exception.Message
            Write-Log "INFO" "HP_BIOSSetting WMI not available: $($_.Exception.Message)"
            return $result
        }
        if ($null -eq $hpSettings -or @($hpSettings).Count -eq 0) {
            $result.Error = 'HP_BIOSSetting returned no instances'
            Write-Log "INFO" "HP_BIOSSetting returned no instances - cannot inspect HP BIOS CA 2023 toggles"
            return $result
        }
        $result.Available = $true
        foreach ($name in $script:HpExpectedBiosSettings.Keys) {
            $row = $hpSettings | Where-Object { $_.Name -eq $name } | Select-Object -First 1
            if ($null -eq $row) {
                $result.Settings[$name] = [pscustomobject]@{
                    Present   = $false
                    Current   = $null
                    Expected  = $script:HpExpectedBiosSettings[$name]
                    Compliant = $false
                }
                $result.NotExposed += $name
                Write-Log "INFO" "HP BIOS setting not exposed by firmware: $name (no SetBIOSSetting attempted)"
                continue
            }
            $current = $row.CurrentValue
            $isCompliant = ($current -eq $script:HpExpectedBiosSettings[$name])
            $result.Settings[$name] = [pscustomobject]@{
                Present   = $true
                Current   = $current
                Expected  = $script:HpExpectedBiosSettings[$name]
                Compliant = $isCompliant
            }
            if (-not $isCompliant) {
                $result.NonCompliant += $name
                Write-Log "WARNING" "HP BIOS setting non-compliant: '$name' is '$current' (expected '$($script:HpExpectedBiosSettings[$name])')"
            }
            else {
                Write-Log "INFO" "HP BIOS setting OK: '$name' = '$current'"
            }
        }
        # AllCompliant ignores NotExposed - if every exposed setting is correct
        # the device is considered configured. Field data shows devices with only
        # 'Enable MS UEFI CA key' exposed (set to Yes) reach 1808 without issue.
        $result.AllCompliant = ($result.NonCompliant.Count -eq 0)
        return $result
    }
    
    # Helper function: Apply the four HP BIOS CA 2023 settings via
    # HP_BIOSSettingInterface.SetBIOSSetting. The BIOS write itself is safe to
    # run on any non-compliant HP device.
    #
    # BitLocker suspend rule (revised per 05-15 field testing):
    # The suspend now fires whenever AT LEAST ONE setting was actually changed
    # in this run (any SetBIOSSetting returning rc=0). The previous logic gated
    # on Test-HpStuckEventPattern, which produced two bugs:
    #   - Enable MS UEFI CA key' flipped No -> Yes
    #     but no stuck-event history -> suspend skipped -> BitLocker recovery
    #     on the next reboot. The cert-rotation transition triggered by the BIOS
    #     change itself is what needs protecting, not the historical stuck loop.
    #   - Historical 1796 still in the log even though the device is at
    #     1808 -> suspend fired on every re-run where no actual BIOS write happened.
    # Tying the suspend to actual writes-made matches what BitLocker actually
    # cares about (the PCR-relevant change), not what the event history says.
    #
    # NamesToFix should already exclude NotExposed settings - the caller is
    # expected to pass $hpBios.NonCompliant (Present-but-wrong only), not
    # NonCompliant + NotExposed. Otherwise SetBIOSSetting will return rc=4
    # for every absent setting.
    function Set-HpBiosCa2023Settings {
        param ([string[]]$NamesToFix)
        $result = [pscustomobject]@{
            SettingsApplied    = @()
            SettingsFailed     = @()
            ChangesMade        = 0
            BitLockerSuspended = $false
            BitLockerSkipped   = $false
            BitLockerError     = $null
            InterfaceError     = $null
        }
        $interface = $null
        try {
            $interface = Get-CimInstance -Namespace 'root\HP\InstrumentedBIOS' -ClassName 'HP_BIOSSettingInterface' -ErrorAction Stop
        }
        catch {
            $result.InterfaceError = $_.Exception.Message
            Write-Log "ERROR" "HP_BIOSSettingInterface not available: $($_.Exception.Message)"
            return $result
        }
        foreach ($name in $NamesToFix) {
            if (-not $script:HpExpectedBiosSettings.Contains($name)) { continue }
            $value = $script:HpExpectedBiosSettings[$name]
            try {
                $invokeRes = Invoke-CimMethod -InputObject $interface -MethodName 'SetBIOSSetting' -Arguments @{
                    Name  = $name
                    Value = $value
                } -ErrorAction Stop
                if ($invokeRes.Return -eq 0) {
                    Write-Log "SUCCESS" "HP BIOS: $name => $value (rc=0)"
                    $result.SettingsApplied += [pscustomobject]@{ Name = $name; Value = $value; Return = 0 }
                }
                else {
                    Write-Log "WARNING" "HP BIOS: $name => $value (rc=$($invokeRes.Return))"
                    $result.SettingsFailed += [pscustomobject]@{ Name = $name; Value = $value; Return = $invokeRes.Return; Error = $null }
                }
            }
            catch {
                Write-Log "ERROR" "HP BIOS: SetBIOSSetting for '$name' threw: $($_.Exception.Message)"
                $result.SettingsFailed += [pscustomobject]@{ Name = $name; Value = $value; Return = -1; Error = $_.Exception.Message }
            }
        }
        $result.ChangesMade = @($result.SettingsApplied).Count
        # Suspend BitLocker for 3 reboots only when an actual BIOS change landed
        # (rc=0). Re-runs that find every setting already correct, or runs that
        # only saw rc=4 (not-exposed) responses, do not touch BitLocker.
        if ($result.ChangesMade -gt 0) {
            try {
                $null = & "$env:SystemRoot\System32\manage-bde.exe" -protectors -disable C: -RebootCount 3 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "SUCCESS" "BitLocker protectors suspended on C: for next 3 reboots ($($result.ChangesMade) BIOS setting(s) changed)"
                    $result.BitLockerSuspended = $true
                }
                else {
                    $result.BitLockerError = "manage-bde exited rc=$LASTEXITCODE (try elevated cmd.exe if it persists)"
                    Write-Log "WARNING" "manage-bde exited rc=$LASTEXITCODE while suspending BitLocker"
                }
            }
            catch {
                $result.BitLockerError = $_.Exception.Message
                Write-Log "WARNING" "manage-bde threw while suspending BitLocker: $($_.Exception.Message)"
            }
        }
        else {
            $result.BitLockerSkipped = $true
            Write-Log "INFO" "BitLocker suspend skipped - no BIOS settings were changed in this run"
        }
        return $result
    }
    
    # Helper function: Detect the HP "BIOS CA 2023 disabled + Boot Manager 2023
    # stuck" pattern. Signature is all three of 1796/1800/1801 present with at
    # least one of them repeating (Count >= 2), confirmed when present by
    # AvailableUpdates pinned at 0x4500 (17664).
    #
    # Freshness gate: if the latest state event is 1808 (compliant), the device
    # has moved past the stuck loop and any 1796/1800/1801 in the log are stale
    # history. Without this gate, a stale 1796 on a now-compliant device (seen
    # on ProBook 450 G10 in field testing) would keep the filter "matched" on
    # every re-run.
    function Test-HpStuckEventPattern {
        param (
            $CertStatus,
            [int]$AvailableUpdatesBits = 0
        )
        if ($null -eq $CertStatus) { return $false }
        # Freshness gate - device has already left the stuck loop.
        if ($CertStatus.EventId -eq 1808) { return $false }
        $hasAll = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1796) -and
                  (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1800) -and
                  (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1801)
        if (-not $hasAll) { return $false }
        $repeated = $false
        if ($null -ne $CertStatus.EventSummary) {
            $hot = @($CertStatus.EventSummary | Where-Object {
                ($_.Id -eq 1796 -or $_.Id -eq 1800 -or $_.Id -eq 1801) -and $_.Count -ge 2
            })
            $repeated = $hot.Count -ge 1
        }
        $confirmedByAv = ($AvailableUpdatesBits -eq 0x4500)
        return ($repeated -or $confirmedByAv)
    }

    # Helper function: Build card section content for both HTML and plain-text formats
    # Returns formatted content lines using the appropriate icons and separators
    # $Format: 'Html' for FontAwesome icons + <br />, 'Local' for emoji + newline
    function Format-CardIcon {
        param (
            [string]$Type,     # check, times, warning, info, sync, ban, clock, eye, building, question
            [string]$Color,    # hex color e.g. '#26A644'
            [string]$Format    # 'Html' or 'Local'
        )
        if ($Format -eq 'Html') {
            $faClass = switch ($Type) {
                'check'    { 'fa-check-circle' }
                'times'    { 'fa-times-circle' }
                'warning'  { 'fa-exclamation-triangle' }
                'info'     { 'fa-info-circle' }
                'sync'     { 'fa-sync-alt' }
                'ban'      { 'fa-ban' }
                'clock'    { 'fa-clock' }
                'eye'      { 'fa-eye' }
                'building' { 'fa-building' }
                'question' { 'fa-question-circle' }
                'circle'   { 'fa-circle' }
                'cog'      { 'fa-cog' }
                default    { 'fa-question' }
            }
            return "<i class='fas $faClass' style='color:$Color;'></i>"
        }
        else {
            $emoji = switch ($Type) {
                'check'    { $script:Emoji.Check }
                'times'    { $script:Emoji.Times }
                'warning'  { $script:Emoji.Warning }
                'info'     { $script:Emoji.Info }
                'sync'     { $script:Emoji.Sync }
                'ban'      { $script:Emoji.Ban }
                'clock'    { $script:Emoji.Clock }
                'eye'      { $script:Emoji.Eye }
                'building' { $script:Emoji.Building }
                'question' { $script:Emoji.Question }
                'circle'   { $script:Emoji.Circle }
                'cog'      { $script:Emoji.Cog }
                default    { $script:Emoji.QuestionWhite }
            }
            return $emoji
        }
    }
    
    # Helper function: Replace FontAwesome <i> icons with emoji equivalents in HTML content
    # Uses the same icon-to-emoji mapping as Format-CardIcon.
    # Handles both quote styles: class='fas ...' (from Format-CardIcon) and class="fas ..." (inline HTML)
    function Convert-FaIconsToEmoji {
        param ([string]$Html)
        if ([string]::IsNullOrEmpty($Html)) { return $Html }
        $faEmojiMap = @{
            'fa-check-circle'          = $script:Emoji.Check
            'fa-times-circle'          = $script:Emoji.Times
            'fa-exclamation-triangle'  = $script:Emoji.Warning
            'fa-exclamation-circle'    = $script:Emoji.ExclamationWhite
            'fa-info-circle'           = $script:Emoji.Info
            'fa-sync-alt'              = $script:Emoji.Sync
            'fa-ban'                   = $script:Emoji.Ban
            'fa-clock'                 = $script:Emoji.Clock
            'fa-eye'                   = $script:Emoji.Eye
            'fa-building'              = $script:Emoji.Building
            'fa-question-circle'       = $script:Emoji.QuestionSmall
            'fa-circle'                = $script:Emoji.Circle
            'fa-cog'                   = $script:Emoji.Cog
            'fa-calendar-check'        = $script:Emoji.Calendar
            'fa-calendar-times'        = $script:Emoji.Calendar
            'fa-redo'                  = $script:Emoji.Sync
            'fa-search'                = $script:Emoji.Search
            'fa-arrow-up-right-from-square' = $script:Emoji.Link
        }
        # Match <i class="fas fa-xxx" style="..."></i> or <i class='fas fa-xxx' style='...'></i>
        # The \s* after </i> consumes the trailing space, add one back after the emoji
        return [regex]::Replace($Html, "<i\s+class=['""]fas\s+(fa-[\w-]+)['""][^>]*>\s*</i>\s*", {
            param($m)
            $cls = $m.Groups[1].Value
            if ($faEmojiMap.ContainsKey($cls)) { "$($faEmojiMap[$cls]) " } else { '' }
        })
    }
    
    # Helper function: Join card lines with HTML line-break separator
    # Both Html (NinjaRMM) and Local (standalone HTML) render as HTML
    function Join-CardLines {
        param (
            [string[]]$Lines,
            [string]$Format  # 'Html' or 'Local' (both use <br />)
        )
        return $Lines -join '<br />'
    }
    
    # Helper function: Build certificate inventory section for card display
    function Build-CertInventorySection {
        param ([string]$Format)
        $lines = @()
        # Platform Key (root of trust) - new in 2026 rev
        if ($pkCerts.Count -gt 0) {
            $pkCn = if ($null -ne $pkSubject) {
                # Extract CN=... value
                $m = [regex]::Match($pkSubject, '(?i)CN=([^,]+)')
                if ($m.Success) { $m.Groups[1].Value.Trim() } else { $pkSubject }
            } else { 'Unknown' }
            if (-not $pkIsTrusted) {
                $pkIcon = Format-CardIcon -Type 'warning' -Color '#D9534F' -Format $Format
                if ($pkSubject -match '(?i)(AMI|DO NOT TRUST)') {
                    $lines += "$pkIcon PK: $pkCn <span style='color:#D9534F;'>(AMI test PK - PKFail / CVE-2024-8105)</span>"
                }
                else {
                    $lines += "$pkIcon PK: $pkCn <span style='color:#D9534F;'>(untrusted placeholder cert)</span>"
                }
            }
            elseif ($pkBlockingKek) {
                # PK is legitimate (OEM cert) but firmware refuses the KEK 2K CA 2023 write (Event 1795)
                # The OEM PK lacks the authority chain needed to authorize the new KEK - OEM BIOS update required
                $pkIcon = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
                $lines += "$pkIcon PK: $pkCn <span style='color:#D9534F;'>(does not authorize/sign KEK 2K CA 2023)</span>"
            }
            elseif ($null -ne $hypervisor) {
                $pkIcon = Format-CardIcon -Type 'info' -Color '#5BC0DE' -Format $Format
                $lines += "$pkIcon PK: $pkCn <span style='color:#888;'>($hypervisor-managed)</span>"
            }
            else {
                $pkIcon = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
                $lines += "$pkIcon PK: $pkCn"
            }
        }
        foreach ($certName in $updatedDbCertNames) {
            $present = $dbCertsFound -contains $certName
            $label   = $certName
            if ($present) {
                # Ground truth wins: cert is physically in db = green regardless of manifest bits
                $icon = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            }
            elseif ($certsUnconfirmed -contains $label) {
                # Manifest bit set but cert not yet in db = blue (pending reboot/processing)
                $icon = Format-CardIcon -Type 'check' -Color '#3B82F6' -Format $Format
            }
            else {
                $icon = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
            }
            $lines += "$icon $label"
        }
        # KEK cert
        if ($has2023InKek) {
            $kekIcon = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
        }
        elseif ($certsUnconfirmed -contains 'KEK 2K CA 2023') {
            $kekIcon = Format-CardIcon -Type 'check' -Color '#3B82F6' -Format $Format
        }
        else {
            $kekIcon = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
        }
        $lines += "$kekIcon KEK 2K CA 2023"
        # 2011 CA revocation status
        if ($ca2011RevokedInDbx.Count -gt 0) {
            foreach ($revokedCA in $ca2011RevokedInDbx) {
                $rLabel = if ($revokedCA -match 'Production PCA') { 'PCA 2011' } elseif ($revokedCA -match 'UEFI CA') { 'UEFI CA 2011' } else { $revokedCA }
                if ($null -ne $svnStatus -and $svnStatus.RevocationAppliedPendingReboot) {
                    # 1037 fired but revocation not yet visible in DBX bytes, needs reboot
                    $rIcon = Format-CardIcon -Type 'ban' -Color '#3B82F6' -Format $Format
                    $lines += "$rIcon $rLabel <span style='color:#888;'>(revoked in dbx - <span style='color:#3B82F6;'>pending reboot</span>)</span>"
                }
                elseif ($null -ne $svnStatus) {
                    $rIcon = Format-CardIcon -Type 'ban' -Color '#26A644' -Format $Format
                    $lines += "$rIcon $rLabel <span style='color:#888;'>(revoked in dbx)</span>"
                }
                else {
                    $rIcon = Format-CardIcon -Type 'ban' -Color '#F59E0B' -Format $Format
                    $lines += "$rIcon $rLabel <span style='color:#888;'>(revoked in dbx)</span>"
                }
            }
        }
        return Join-CardLines -Lines $lines -Format $Format
    }
    
    # Helper function: Build PK Security Alert section (PKFail / CVE-2024-8105)
    # Only rendered when $statusKey is 'PKUntrusted'. Red-tinted div with a two-<details>
    # structure (collapsed "Why is this critical?" + expanded "How to fix?") and a
    # References footer. Uses Format-CardIcon for the header icon so the Local (emoji)
    # output stays 1:1 with the Html (FontAwesome) output. The body is format-agnostic
    # HTML that renders identically in both targets.
    function Build-PkSecurityAlertSection {
        param ([string]$Format)
        $cveUrl      = 'https://nvd.nist.gov/vuln/detail/CVE-2024-8105'
        $certccUrl   = 'https://github.com/CERTCC/PKfail/'
        $msDocsUrl   = 'https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11'
        $msOemPkUrl  = 'https://go.microsoft.com/fwlink/?linkid=2255361'
        $arsRundown  = 'https://arstechnica.com/security/2024/07/secure-boot-is-completely-compromised-on-200-models-from-5-big-device-makers'
        $oemBiosGuide = Get-OemBIOSUpdateGuide
        $oemGuideLine = if ($oemBiosGuide) {
            '<a href="' + $oemBiosGuide + '" target="_blank" rel="nofollow noopener noreferrer">OEM BIOS/Firmware Update Guide</a>'
        } else { 'Check the OEM support site for the latest BIOS/firmware.' }
        $pkSubjectSafe = [System.Net.WebUtility]::HtmlEncode($pkSubject)
        $headerIcon = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
        
        # Theme-aware alert colors via CSS custom properties with hard-coded fallbacks:
        #   Local (light mode): --alert-bg = #FDECEA, --alert-text = #272727 (matches Ninja's look)
        #   Local (dark mode):  --alert-bg = #3a1518 (desaturated dark red), --alert-text = #e5e7eb
        #   Ninja (Html path):  neither var is defined, so the fallback after the comma applies
        #                       and the existing light-pink look is preserved.
        # max-width:767px caps line length on wide monitors so paragraphs wrap at a comfortable
        # reading width (~85 chars) instead of sprawling across 1500px+ of card real estate.
        return '<div style="border-left:3px solid #D9534F;padding:6px 10px;background:var(--alert-bg,#FDECEA);color:var(--alert-text,#272727);max-width:767px;">' +
            $headerIcon + ' <b style="color:#D9534F;">PKFail / CVE-2024-8105</b><br />' +
            'PK subject: <code>' + $pkSubjectSafe + '</code><br /><br />' +
            '<details><summary style="cursor:pointer;"><b>Why is this critical?</b></summary>' +
            '<div style="margin-top:6px;">' +
            '<b>What the AMI Test PK is.</b> A placeholder Platform Key shipped in AMI Aptio V ' +
            'reference firmware. The private key leaked publicly in 2024. Any party can sign ' +
            'KEK/db/dbx updates that the firmware accepts as authoritative.<br /><br />' +
            '<b>Why "Compliant" would be misleading.</b> Even with the 2023 certs physically present ' +
            'in db, a threat actor could re-enroll a rogue KEK, and then add their own db ' +
            'entries, bypassing Microsoft''s revocations. Compliance is good on paper, ' +
            'but considered un-safe in the real world.<br /><br />' +
            '<b>The rundown:</b> ' +
            '<a href="' + $arsRundown + '" target="_blank" rel="nofollow noopener noreferrer">Ars Technica: Secure Boot is completely compromised on 200 models from 5 big device makers</a>.' +
            '</div></details>' +
            '<details open><summary style="cursor:pointer;"><b>How to fix?</b></summary>' +
            '<div style="margin-top:6px;">' +
            '<b>1. Permanent (strongly preferred):</b> request a BIOS/firmware update from the ' +
            'OEM that ships a legitimate (OEM-managed) PK from factory.<br />' +
            '&nbsp;&nbsp;' + $oemGuideLine + '<br /><br />' +
            '<b>2. Temporary mitigation:</b> the ' +
            '<a href="' + $certccUrl + '" target="_blank" rel="nofollow noopener noreferrer">CERT/CC PKFail script</a> ' +
            'uses the known AMI private key to re-sign and enroll ' +
            '<a href="' + $msOemPkUrl + '" target="_blank" rel="nofollow noopener noreferrer">Microsoft''s Windows OEM Devices PK</a>. ' +
            'Enrollment is not persistent across firmware resets on all devices.<br /><br />' +
            '<b>3. Before either approach:</b> suspend BitLocker on every protected volume. ' +
            'Replacing the PK can invalidate TPM-sealed recovery keys.' +
            '</div></details>' +
            '<div style="margin-top:8px;font-size:0.9em;">' +
            'References: <br />' +
            '&nbsp;&nbsp;&bull; <a href="' + $cveUrl + '" target="_blank" rel="nofollow noopener noreferrer">CVE-2024-8105</a><br />' +
            '&nbsp;&nbsp;&bull; <a href="' + $certccUrl + '" target="_blank" rel="nofollow noopener noreferrer">CERT/CC PKfail</a><br />' +
            '&nbsp;&nbsp;&bull; <a href="' + $msDocsUrl + '" target="_blank" rel="nofollow noopener noreferrer">Microsoft Secure Boot key guidance</a><br />' +
            '&nbsp;&nbsp;&bull; <a href="' + $arsRundown + '" target="_blank" rel="nofollow noopener noreferrer">Ars Technica rundown</a>' +
            '</div>' +
            '</div>'
    }
    
    # Helper function: Build factory defaults section (shown only when defaults are missing)
    function Build-FactoryDefaultsSection {
        param ([string]$Format)
        $lines = @()
        $order = 'PKDefault','KEKDefault','dbDefault','dbxDefault'
        foreach ($n in $order) {
            if ($defaultsPresent[$n]) {
                $ic = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
                $lines += "$ic ${n}: present"
            }
            else {
                $ic = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
                $lines += "$ic ${n}: missing"
            }
        }
        if ($defaultsAllMissing) {
            $warn = Format-CardIcon -Type 'warning' -Color '#D9534F' -Format $Format
            $lines += "<span style='color:#D9534F;'>$warn All UEFI default databases are missing - BIOS 'Reset Secure Boot keys' option will not function.</span>"
            # Manual resolution
            $lines += "<details><summary style='cursor:pointer;'>Manual resolution</summary><div style='margin-left:1em; font-size:0.9em;'>Shut down and enter the UEFI Secure Boot menu. Under <i>PK Options</i> (or <i>Key Management &rarr; PK Management</i>), enroll <code>\EFI\Certs\WindowsOEMDevicesPK.der</code> from the EFI partition. Under <i>KEK Options</i> (or <i>Key Management &rarr; KEK Management &rarr; Append Key</i>), enroll <code>\EFI\Updates\Microsoft Corporation KEK 2K CA 2023.der</code>. Save, exit, boot Windows, and re-run this script.<br /><br />If your OEM BIOS does not expose these menus, an OEM firmware update is required.</div></details>"
        }
        elseif ($defaultsSomeMissing) {
            $missing = $order | Where-Object { -not $defaultsPresent[$_] }
            $info = Format-CardIcon -Type 'info' -Color '#F0AD4E' -Format $Format
            $lines += "<span style='color:#F0AD4E;'>$info Partial defaults: $($missing -join ', ') missing.</span>"
            # KEK-only manual resolution
            if ($missing -contains 'KEKDefault' -and $missing -notcontains 'PKDefault') {
                $lines += "<details><summary style='cursor:pointer;'>Manual KEK resolution</summary><div style='margin-left:1em; font-size:0.9em;'>Shut down and enter the UEFI Secure Boot menu. Under <i>KEK Options</i> (or <i>Key Management &rarr; KEK Management &rarr; Append Key</i>), enroll <code>\EFI\Certs\Microsoft Corporation KEK 2K CA 2023.der</code> (fall back to <code>.crt</code> if the <code>.der</code> errors). Save, exit, boot Windows, and re-run this script.</div></details>"
            }
        }
        return Join-CardLines -Lines $lines -Format $Format
    }
    
    # Helper function: Build HP BIOS CA 2023 interface section for card display.
    # Branches:
    #   - WMI not available / not HP -> returns $null (caller skips the section)
    #   - AllCompliant (every exposed toggle in expected state) -> green header
    #     listing each setting; NotExposed entries shown in blue as informational
    #     ("not exposed by this firmware - normal for this model").
    #   - NonCompliant + stuck pattern matched -> red "Action Required"
    #   - NonCompliant + currently 1808 -> amber latent-risk
    #   - NonCompliant + neither -> amber filter-not-matched
    # Always renders the remediation outcome when $Remediation is supplied,
    # the per-setting state grid, and the OEM guide link. The manual <details>
    # block is shown when the auto-write was skipped (audit mode) or the
    # interface was unavailable.
    function Build-HpBiosSection {
        param (
            [string]$Format,
            $HpBios,
            [bool]$StuckPattern,
            $Remediation
        )
        if ($null -eq $HpBios -or -not $HpBios.Available) { return $null }
        # Wrap long paragraphs at a comfortable reading width. max-width caps
        # the paragraph so the "Why this is flagged" block stops overflowing
        # the card. Other rows are short enough to not need the wrapper.
        $paraStyle = 'display:block;max-width:767px;'
        $lines = @()
        
        $currentlyCompliant = $false
        if ($null -ne $certStatus -and $certStatus.EventId -eq 1808) { $currentlyCompliant = $true }
        $notExposedCount = @($HpBios.NotExposed).Count
        $notExposedNote = if ($notExposedCount -gt 0) {
            " <span style='color:#888;font-size:0.9em;'>($notExposedCount toggle$(if ($notExposedCount -ne 1) { 's' }) not exposed by this firmware - normal for many HP models)</span>"
        } else { '' }
        
        # --- Header --------------------------------------------------------
        if ($HpBios.AllCompliant) {
            $ic = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            $lines += "$ic HP BIOS CA 2023 interface configured correctly$notExposedNote"
        }
        elseif ($StuckPattern) {
            $hdrIc = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
            $lines += "<span style='color:#D9534F;'>$hdrIc HP BIOS CA 2023 disabled while OS is stuck on Boot Manager 2023 (1796 + 1800 + 1801 repeating)</span>$notExposedNote"
        }
        elseif ($currentlyCompliant) {
            $hdrIc = Format-CardIcon -Type 'warning' -Color '#F0AD4E' -Format $Format
            $lines += "<span style='color:#F0AD4E;'>$hdrIc HP BIOS CA 2023 toggles disabled - device currently passing (Event 1808) but latent risk on the next cert/SVN rotation</span>$notExposedNote"
        }
        else {
            $hdrIc = Format-CardIcon -Type 'warning' -Color '#F0AD4E' -Format $Format
            $lines += "<span style='color:#F0AD4E;'>$hdrIc HP BIOS CA 2023 toggles disabled - stuck-state fingerprint not detected in current event window</span>$notExposedNote"
        }
        
        # --- Per-setting state grid ----------------------------------------
        # Only exposed settings get a row. NotExposed toggles are omitted
        # entirely - listing every "not exposed by firmware" line wastes card
        # space and the absence of the row is itself the indicator. The
        # not-exposed count is still summarized in the header parenthetical.
        foreach ($name in $script:HpExpectedBiosSettings.Keys) {
            $s = $HpBios.Settings[$name]
            if (-not $s.Present) { continue }
            if ($s.Compliant) {
                $rowIc = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
                $lines += "&nbsp;&nbsp;$rowIc ${name}: $($s.Current)"
            }
            else {
                $rowIc = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
                $lines += "&nbsp;&nbsp;$rowIc ${name}: <span style='color:#D9534F;'>$($s.Current)</span> &rarr; expected <span style='color:#26A644;'>$($s.Expected)</span>"
            }
        }
        
        # --- Significance paragraph (non-stuck branches only) --------------
        # Stuck branch is self-explanatory from the red header. Non-stuck
        # branches need to explain WHY the section was rendered when nothing
        # is currently failing on the device. Split into short sentences and
        # paragraphs (`<br /><br />`) so the block reads cleanly inside the
        # max-width wrapper.
        if (-not $StuckPattern -and -not $HpBios.AllCompliant) {
            $info = Format-CardIcon -Type 'info' -Color '#5BC0DE' -Format $Format
            if ($currentlyCompliant) {
                $body =
                    "<b>Why this is flagged.</b> The OS-side cert rotation has finished against the existing UEFI db (Event 1808), " +
                    "but the HP BIOS-level CA 2023 toggles are still disabled.<br /><br />" +
                    "<b>Why it still matters.</b> Any future BIOS reset, key clear, SVN enforcement, or dbx revocation cycle re-enters " +
                    "the Boot Manager 2023 transition. On this firmware configuration those writes are rejected - producing the " +
                    "1796 / 1800 / 1801 loop and BitLocker recovery already seen on other HP units. Correcting now is preventative."
            }
            else {
                $body =
                    "<b>Why this is flagged.</b> The HP BIOS-level CA 2023 toggles are disabled. The 1796 / 1800 / 1801 stuck-loop " +
                    "fingerprint is not in the current event window, but this configuration consistently stalls the Boot Manager " +
                    "2023 step on HP devices once Windows Update next reaches that transition.<br /><br />" +
                    "<b>Action.</b> The BIOS write applies regardless of the filter. BitLocker is suspended only when an actual " +
                    "toggle change lands (rc=0)."
            }
            $lines += "$info <span style=`"$paraStyle`">$body</span>"
        }
        
        # --- Remediation outcome (any run that attempted writes) -----------
        if ($null -ne $Remediation) {
            $appliedCount = @($Remediation.SettingsApplied).Count
            $failedCount  = @($Remediation.SettingsFailed).Count
            $changesMade  = if ($null -ne $Remediation.ChangesMade) { $Remediation.ChangesMade } else { $appliedCount }
            if ($null -ne $Remediation.InterfaceError) {
                $errIc = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
                $lines += "<span style='color:#D9534F;'>$errIc Auto-remediation skipped: HP_BIOSSettingInterface unavailable ($($Remediation.InterfaceError)). Use the manual block below.</span>"
            }
            elseif ($appliedCount -eq 0 -and $failedCount -eq 0) {
                $infoIc = Format-CardIcon -Type 'info' -Color '#5BC0DE' -Format $Format
                $lines += "$infoIc Auto-remediation: nothing to write (no eligible non-compliant exposed toggles)."
            }
            elseif ($appliedCount -gt 0 -and $failedCount -eq 0) {
                $okIc = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
                $lines += "<span style='color:#26A644;'>$okIc Auto-remediation applied: $appliedCount setting(s) corrected via HP_BIOSSettingInterface (rc=0). Reboot to absorb.</span>"
            }
            elseif ($appliedCount -gt 0 -and $failedCount -gt 0) {
                $warnIc = Format-CardIcon -Type 'warning' -Color '#F0AD4E' -Format $Format
                $lines += "<span style='color:#F0AD4E;'>$warnIc Auto-remediation partial: $appliedCount applied (rc=0), $failedCount rejected (see per-setting detail).</span>"
            }
            elseif ($failedCount -gt 0) {
                $errIc = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
                $lines += "<span style='color:#D9534F;'>$errIc Auto-remediation failed: all $failedCount SetBIOSSetting calls returned non-zero. Escalate to HP with model + BIOS version.</span>"
            }
            foreach ($r in @($Remediation.SettingsFailed)) {
                $rowIc = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
                $detail = if ($null -ne $r.Error) { $r.Error } else { "rc=$($r.Return)" }
                $lines += "&nbsp;&nbsp;$rowIc $($r.Name): <span style='color:#D9534F;'>$detail</span>"
            }
            # BitLocker suspend - driven by writes-made, not by stuck filter.
            if ($Remediation.BitLockerSuspended) {
                $blIc = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
                $lines += "$blIc BitLocker protectors suspended on C: for next 3 reboots ($changesMade BIOS change(s) landed - PCR-safe boot path)"
            }
            elseif ($null -ne $Remediation.BitLockerError) {
                $blIc = Format-CardIcon -Type 'warning' -Color '#F0AD4E' -Format $Format
                $lines += "<span style='color:#F0AD4E;'>$blIc BitLocker suspend failed: $($Remediation.BitLockerError). Re-run from elevated cmd.exe if recovery prompts appear on reboot.</span>"
            }
            elseif ($Remediation.BitLockerSkipped) {
                $blIc = Format-CardIcon -Type 'info' -Color '#5BC0DE' -Format $Format
                $lines += "$blIc BitLocker suspend not run - no BIOS settings were changed in this run."
            }
        }
        
        # --- Manual fallback (audit mode or interface error) ---------------
        # Auto-write was the answer when it could run; only surface the manual
        # block when the script couldn't execute it. Removes noise from runs
        # where the script already did the work.
        $needsManualBlock = ($null -eq $Remediation) -or
                            ($null -ne $Remediation -and $null -ne $Remediation.InterfaceError)
        if ($needsManualBlock) {
            $manualBlock = @'
<details><summary style="cursor:pointer;"><b>Manual remediation (run elevated)</b></summary>
<div style="margin-top:6px;font-size:0.9em;max-width:767px;">
<b>Step 1.</b> Apply the four HP BIOS CA 2023 toggles via WMI. <code>rc=4</code> means the setting is not exposed on this firmware (skip), <code>rc=0</code> means applied.
<pre style="background:var(--code-bg,#f4f4f4);color:var(--code-text,#272727);padding:8px;border-radius:4px;overflow-x:auto;">$bios = Get-CimInstance -Namespace root\HP\InstrumentedBIOS -ClassName HP_BIOSSettingInterface
Invoke-CimMethod -InputObject $bios -MethodName SetBIOSSetting -Arguments @{Name='Windows UEFI CA 2023';Value='Enable'}
Invoke-CimMethod -InputObject $bios -MethodName SetBIOSSetting -Arguments @{Name='Microsoft Option ROM UEFI CA 2023';Value='Enable'}
Invoke-CimMethod -InputObject $bios -MethodName SetBIOSSetting -Arguments @{Name='Microsoft UEFI CA 2023';Value='Enable'}
Invoke-CimMethod -InputObject $bios -MethodName SetBIOSSetting -Arguments @{Name='Enable MS UEFI CA key';Value='Yes'}</pre>
On models where only 'Enable MS UEFI CA key' is exposed, that single setting is usually sufficient for the cert rotation to complete.<br /><br />
<b>Step 2.</b> If at least one setting actually changed (any rc=0), suspend BitLocker for the next three reboots. <code>manage-bde.exe</code> can return Access Denied from PowerShell on some hosts; if so, run from elevated <b>cmd.exe</b>:
<pre style="background:var(--code-bg,#f4f4f4);color:var(--code-text,#272727);padding:8px;border-radius:4px;overflow-x:auto;">manage-bde -protectors -disable C: -RebootCount 3</pre>
Skip this step if every setting was already correct - no BIOS change means no PCR drift and no recovery prompt.<br /><br />
<b>Step 3.</b> Reboot. Re-run this script to confirm the exposed toggles report as Enabled and Event 1808 remains the latest state event.
</div></details>
'@
            $lines += $manualBlock
        }
        
        $oemBiosGuide = Get-OemBIOSUpdateGuide
        if ($oemBiosGuide) {
            $linkIc = Format-CardIcon -Type 'building' -Color '#5BC0DE' -Format $Format
            $lines += "$linkIc <a href='$oemBiosGuide' target='_blank' rel='nofollow noopener noreferrer'>HP BIOS / firmware update guide</a>"
        }
        return Join-CardLines -Lines $lines -Format $Format
    }
    
    # Helper function: Build servicing status section for card display
    function Build-ServicingSection {
        param ([string]$Format)
        $parts = @()
        if ($null -ne $servicingStatus.UEFICA2023Status) {
            $icon = if ($servicingStatus.UEFICA2023Status -eq 'Updated') {
                Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            }
            else {
                Format-CardIcon -Type 'info' -Color '#F0AD4E' -Format $Format
            }
            $label = 'Service Status'
            $parts += "$icon ${label}: $($servicingStatus.UEFICA2023Status)"
        }
        if ($null -ne $servicingStatus.WindowsUEFICA2023Capable) {
            $capVal = $servicingStatus.WindowsUEFICA2023Capable
            $capDesc = switch ($capVal) { 1 { 'Cert in DB' }; 2 { 'Cert in DB + 2023 boot manager' }; default { 'Not in DB' } }
            $capIcon = if ($capVal -ge 2) { Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format }
                       elseif ($capVal -eq 1) { Format-CardIcon -Type 'info' -Color '#5BC0DE' -Format $Format }
                       else { Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format }
            $parts += "$capIcon Boot Manager: $capDesc"
        }
        if ($null -ne $servicingStatus.UEFICA2023Error -and $servicingStatus.UEFICA2023Error -ne 0) {
            $errIcon = Format-CardIcon -Type 'warning' -Color '#D9534F' -Format $Format
            $parts += "$errIcon Error: $($servicingStatus.UEFICA2023ErrorHex) - $($servicingStatus.UEFICA2023ErrorMessage)"
        }
        if ($null -ne $servicingStatus.UEFICA2023ErrorEvent) {
            $eeIcon = Format-CardIcon -Type 'info' -Color '#D9534F' -Format $Format
            $parts += "$eeIcon Error Event: [$($servicingStatus.UEFICA2023ErrorEvent)] $($servicingStatus.UEFICA2023ErrorEventDesc)"
        }
        if ($null -ne $servicingStatus.CanAttemptUpdateAfter -and $servicingStatus.CanAttemptUpdateAfter -gt (Get-Date)) {
            $updateAfterStr = $servicingStatus.CanAttemptUpdateAfter.ToString('yyyy-MM-dd HH:mm')
            $clkIcon = Format-CardIcon -Type 'clock' -Color '#F0AD4E' -Format $Format
            $parts += "$clkIcon Next attempt after: $updateAfterStr"
        }
        if ($parts.Count -eq 0) { return $null }
        return Join-CardLines -Lines $parts -Format $Format
    }
    
    # Helper function: Build Updates/manifest section for card display
    function Build-UpdatesSection {
        param ([string]$Format)
        if ($allApplied -and -not $svnRebootForManifest) {
            $chk = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            return "$chk No Updates Pending <span style='color:#26A644;'>(all applied)</span>"
        }
        # Build header note
        if ($allApplied -and $svnRebootForManifest) {
            $hdrNote = " <span style='color:#3B82F6; font-size:0.85em;'>(all certs applied - pending SVN reboot)</span>"
        }
        elseif ($allApplied) {
            $hdrNote = " <span style='color:#26A644;'>(all applied)</span>"
        }
        elseif ($pendingReboot) {
            $certCount = $manifestPending.Count
            $s = if ($certCount -ne 1) { 's' } else { '' }
            $hdrNote = " <span style='color:#3B82F6;'>(pending cert reboot for $certCount cert$s)</span>"
        }
        else {
            $pc = $manifestPending.Count
            $hdrNote = " <span style='color:#F0AD4E;'>($pc pending)</span>"
        }
        $pendingIconColor = if ($svnRebootForManifest -or $pendingReboot) { '#3B82F6' } else { '#5BC0DE' }
        $pendIcon = Format-CardIcon -Type 'info' -Color $pendingIconColor -Format $Format
        $lines = @("$pendIcon Pending$hdrNote")
        foreach ($m in $enrichedMeaning) {
            $lines += "&nbsp;&nbsp;&bull; $m"
        }
        if ($manifestPending.Count -gt 0) {
            $warnIcon = Format-CardIcon -Type 'warning' -Color '#F0AD4E' -Format $Format
            $lines += "<span style='color:#F0AD4E;'>$warnIcon Still needed: $($manifestPending -join ', ')</span>"
            if ($pendingReboot) {
                $syncIcon = Format-CardIcon -Type 'sync' -Color '#F0AD4E' -Format $Format
                $lines += "<span style='color:#F0AD4E;'>$syncIcon Reboot pending (Event 1800) to apply remaining certs</span>"
            }
        }
        return Join-CardLines -Lines $lines -Format $Format
    }
    
    # Helper function: Build enforcement mitigation lines (shared by active and passive enforcement display)
    function Build-EnforcementMitigationLines {
        param (
            [string]$Format,
            [hashtable]$EnfResult,          # The enforcement result hashtable
            [bool]$SvnRebootPending,        # Whether SVN reboot is pending (firmware SVN mismatch)
            [bool]$RevocationRebootPending, # Whether revocation is pending reboot (1037 fired but not yet in DBX)
            [bool]$SvnPendingUpdate = $false,           # Whether it's a benign component-level bump (firmware at prior SVN)
            [string[]]$SvnPendingUpdateComponents = @(),# Which boot-components are pending (BootMgr/CdBoot/WdsMgr)
            [bool]$SvnNotApplied = $false,              # Whether firmware refused to absorb after reboot (stuck state)
            [string[]]$SvnNotAppliedComponents = @()    # Which boot-components were not applied (BootMgr/CdBoot/WdsMgr)
        )
        $mitigations = @(
            @{ Key = 'Mitigation1'; Label = 'Windows CA2023' }
            @{ Key = 'Mitigation2'; Label = 'Boot manager' }
            @{ Key = 'Mitigation3'; Label = '2011 revocation' }
            @{ Key = 'Mitigation4'; Label = 'SVN update' }
        )
        $rebootRequired = $EnfResult.RebootRequired
        $lines = @()
        foreach ($m in $mitigations) {
            $state = $EnfResult[$m.Key]
            $blockedReason = $EnfResult["$($m.Key)BlockedReason"]
            $isMit12 = $m.Key -in @('Mitigation1', 'Mitigation2')
            $isMit34 = $m.Key -in @('Mitigation3', 'Mitigation4')
            # Mit 1+2: show reboot pending when applied but overall reboot required
            $mit12RebootPending = ($isMit12 -and $rebootRequired -and $state -eq 'Applied')
            # Mit 3: only "pending reboot" when revocation not yet visible in DBX
            # Mit 4: "pending SVN reboot" when firmware SVN hasn't absorbed the update
            $mit3RevocReboot = ($m.Key -eq 'Mitigation3' -and $RevocationRebootPending -and $state -in @('AlreadyApplied', 'Applied'))
            $mit4SvnReboot   = ($m.Key -eq 'Mitigation4' -and $SvnRebootPending -and $state -in @('AlreadyApplied', 'Applied'))
            $mit34SvnReboot  = ($mit3RevocReboot -or $mit4SvnReboot)
            $mIcon = switch ($state) {
                'AlreadyApplied' { Format-CardIcon -Type 'check' -Color $(if ($mit34SvnReboot) { '#3B82F6' } else { '#26A644' }) -Format $Format }
                'Applied'        { Format-CardIcon -Type $(if ($mit12RebootPending) { 'sync' } else { 'check' }) -Color '#3B82F6' -Format $Format }
                'Blocked'        { Format-CardIcon -Type 'ban' -Color '#F59E0B' -Format $Format }
                'Failed'         { Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format }
                default          { Format-CardIcon -Type 'circle' -Color '#6B7280' -Format $Format }
            }
            # Mitigation 4 row wording has three tiers, most-specific first:
            #   * SvnNotApplied   -> RED "Not applied (X) - firmware refused after reboot"
            #   * SvnPendingUpdate -> BLUE "Pending SVN update (X)" (benign bump)
            #   * else             -> BLUE "Pending SVN reboot" (generic fallback)
            # Mitigation 3's revocation-reboot wording stays as-is (different signal).
            $mit4NotApplied    = ($m.Key -eq 'Mitigation4' -and $SvnNotApplied -and $mit4SvnReboot)
            $mit4PendingUpdate = ($m.Key -eq 'Mitigation4' -and $SvnPendingUpdate -and $mit4SvnReboot)
            $svnPendingLabel = if ($mit4NotApplied -and $SvnNotAppliedComponents.Count -gt 0) {
                "<span style='color:#D9534F;'>Not applied (" + ($SvnNotAppliedComponents -join ', ') + ') - firmware refused after reboot</span>'
            } elseif ($mit4PendingUpdate -and $SvnPendingUpdateComponents.Count -gt 0) {
                "<span style='color:#3B82F6;'>Pending SVN update (" + ($SvnPendingUpdateComponents -join ', ') + ')</span>'
            } else {
                "<span style='color:#3B82F6;'>Pending SVN reboot</span>"
            }
            $stateLabel = switch ($state) {
                'AlreadyApplied' {
                    if ($mit34SvnReboot) { $svnPendingLabel }
                    else { 'Complete' }
                }
                'Applied' {
                    if ($mit12RebootPending) { "<span style='color:#3B82F6;'>Reboot pending</span>" }
                    elseif ($mit34SvnReboot) { $svnPendingLabel }
                    else { 'Applied' }
                }
                'Blocked' {
                    if ($blockedReason) { "<span style='color:#F59E0B;'>$blockedReason</span>" }
                    else { 'Blocked' }
                }
                'Failed'  { 'Failed' }
                default   {
                    if ($isMit34) { "<span style='color:#6B7280;'>Awaiting enforcement (June 2026 - 2027)</span>" }
                    elseif ($isMit12) { "<span style='color:#6B7280;'>Not yet applied</span>" }
                    else { "<span style='color:#6B7280;'>Pending</span>" }
                }
            }
            $lines += "$mIcon $($m.Label): $stateLabel"
        }
        return $lines
    }
    
    # =======================================================================
    # SVN BITLOCKER SAFETY CARD SECTION
    # =======================================================================
    function Build-SvnBitLockerSection {
        param (
            [string]$Format,
            $Result
        )
        
        if ($null -eq $Result) { return $null }
        
        $status = [string]$Result.Status
        $statusLine = switch ($status) {
            'Suspended' {
                "$(Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format) BitLocker safety window prepared"
            }
            'SuspendedWithExisting' {
                "$(Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format) BitLocker safety window prepared"
            }
            'AlreadySuspended' {
                "$(Format-CardIcon -Type 'info' -Color '#3B82F6' -Format $Format) Eligible volumes were already suspended"
            }
            'NoProtectedVolumes' {
                "$(Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format) No encrypted OS/fixed-data BitLocker volumes found"
            }
            'Disabled' {
                "$(Format-CardIcon -Type 'warning' -Color '#F59E0B' -Format $Format) Automatic suspension disabled by SuspendBitlockerForSVN"
            }
            'Failed' {
                if ($Result.PendingManifest) {
                    "$(Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format) BitLocker suspension failed - Stage 3/4 is already pending; do not reboot"
                }
                else {
                    "$(Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format) BitLocker suspension failed - Stage 3/4 trigger blocked"
                }
            }
            'UnsafeManifest' {
                "$(Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format) Unsafe Stage 3/4 bits could not be cleared - task blocked; do not reboot"
            }
            default {
                if (-not $Result.Enabled) {
                    "$(Format-CardIcon -Type 'warning' -Color '#F59E0B' -Format $Format) Automatic suspension is disabled; no Stage 3/4 bits require action this run"
                }
                else {
                    "$(Format-CardIcon -Type 'info' -Color '#6B7280' -Format $Format) No Stage 3/4 BitLocker suspension required this run"
                }
            }
        }
        
        $lines = @($statusLine)
        $stages = @($Result.Stages | ForEach-Object { [System.Net.WebUtility]::HtmlEncode([string]$_) })
        if ($stages.Count -gt 0) {
            $lines += "&nbsp;&nbsp;&bull; SVN operation: $($stages -join ' + ')"
        }
        
        $suspended = @($Result.SuspendedVolumes | ForEach-Object { [System.Net.WebUtility]::HtmlEncode([string]$_) })
        if ($suspended.Count -gt 0) {
            $rebootCount = [int]$Result.RebootCount
            $lines += "&nbsp;&nbsp;&bull; Suspended for $rebootCount reboots: $($suspended -join ', ')"
        }
        
        $alreadySuspended = @($Result.AlreadySuspendedVolumes | ForEach-Object { [System.Net.WebUtility]::HtmlEncode([string]$_) })
        if ($alreadySuspended.Count -gt 0) {
            $lines += "&nbsp;&nbsp;&bull; Already suspended (left unchanged): $($alreadySuspended -join ', ')"
        }
        
        $skipped = @($Result.SkippedVolumes | ForEach-Object { [System.Net.WebUtility]::HtmlEncode([string]$_) })
        if ($skipped.Count -gt 0) {
            $lines += "&nbsp;&nbsp;&bull; Skipped: $($skipped -join ', ')"
        }
        
        $failed = @($Result.FailedVolumes | ForEach-Object { [System.Net.WebUtility]::HtmlEncode([string]$_) })
        if ($failed.Count -gt 0) {
            $lines += "<span style='color:#D9534F;'>&nbsp;&nbsp;&bull; Failed: $($failed -join ', ')</span>"
        }
        
        return Join-CardLines -Lines $lines -Format $Format
    }
    # =======================================================================
    # END SVN BITLOCKER SAFETY CARD SECTION
    # =======================================================================
    
    # Helper function: Build SVN compliance section for card display
    function Build-SvnComplianceSection {
        param ([string]$Format)
        # Status icon and label
        # Three-way split of "1-2 of 3 SVN components missing from DBX":
        #
        #   * Benign pending update (the common case): every missing component has a
        #     PRIOR firmware SVN (FirmwareSvn populated and < RequiredSvn). The
        #     absorb mechanism proved working last round; firmware is just waiting
        #     for the next boot-time apply of the next increment. This is now
        #     distinguishable reliably thanks to the raw-DBX max-SVN fix (see
        #     Get-DbxBootMgrSVN / PowerShell#27058) - pre-fix the cmdlet's order-
        #     dependent FirmwareSVN made "prior SVN" unreliable. Label:
        #     "Pending SVN Update".
        #
        #   * True partial-commit rejection: at least one missing component has
        #     no firmware SVN at all while others have advanced. Firmware is
        #     selectively refusing to absorb. Reboot will not resolve - needs a
        #     BIOS update or OEM escalation. Label: "Firmware partial-commit
        #     rejected".
        #
        # "All three missing" is handled by the lower branches (RebootPending /
        # RevocationPending) because that's the pre-reboot or pre-rollout pattern,
        # not component-asymmetric.
        # Read the pre-computed pending-update / not-applied classification from
        # $svnStatus - decorated by the early DBX validation pass in the outer scope
        # using Event 1034/1042 + lastBootTime to distinguish pre-reboot bumps from
        # firmware-had-its-chance refusals. Partial-commit is still computed locally
        # since it's not surfaced on $svnStatus (it's the residual asymmetric case).
        $svnNotApplied      = ($null -ne $svnStatus.SvnNotApplied -and $svnStatus.SvnNotApplied)
        $svnNotAppliedComps = @($svnStatus.SvnNotAppliedComponents)
        $svnPendingUpdate   = ($null -ne $svnStatus.PendingUpdate -and $svnStatus.PendingUpdate)
        $svnPendingNames    = @($svnStatus.PendingUpdateComponents)
        $svnPartialCommit   = $false
        $svnPartialNames    = @()
        if ($null -ne $dbxValidationResult -and $dbxValidationResult.Succeeded) {
            $svnMissing = @($dbxValidationResult.MissingComponents)
            if ($svnMissing.Count -gt 0 -and $svnMissing.Count -lt 3) {
                $allHavePriorSvn = $true
                foreach ($m in $svnMissing) {
                    if ([string]::IsNullOrWhiteSpace([string]$m.FirmwareSvn)) {
                        $allHavePriorSvn = $false
                        break
                    }
                }
                if (-not $allHavePriorSvn) {
                    $svnPartialCommit = $true
                    $svnPartialNames  = @($svnMissing | ForEach-Object { $_.Component })
                }
            }
        }
        
        if ($svnStatus.IsCompliant) {
            $svnIcon  = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            $svnLabel = $svnStatus.ComplianceStatus
        }
        elseif ($svnNotApplied) {
            # Firmware had its chance and refused - reboot already happened since
            # the scheduled task's DBX write (Event 1034/1042 predates lastBootTime).
            # This is a firmware-level refusal. Must come before PendingUpdate/RebootPending
            # since those would mask it.
            $svnIcon  = Format-CardIcon -Type 'warning' -Color '#D9534F' -Format $Format
            $compList = $svnNotAppliedComps -join ', '
            $svnLabel = "SVN Update Not Applied ($compList) <span style='color:#888;'>(OEM escalation may be required)</span>"
        }
        elseif ($svnPartialCommit) {
            $svnIcon  = Format-CardIcon -Type 'warning' -Color '#D9534F' -Format $Format
            $compList = $svnPartialNames -join ', '
            $svnLabel = "Firmware partial-commit: $compList SVN rejected <span style='color:#888;'>(reboot will not resolve - BIOS update or OEM escalation)</span>"
        }
        elseif ($svnPendingUpdate) {
            # Benign bump-pending state. Must come before the generic RebootPending
            # branch because it names the specific component(s) awaiting the apply,
            # which is strictly more informative than "SVN update not yet applied".
            $svnIcon  = Format-CardIcon -Type 'sync' -Color '#F59E0B' -Format $Format
            $compList = $svnPendingNames -join ', '
            $svnLabel = "Pending SVN Update ($compList) <span style='color:#888;'>(firmware at prior SVN, reboot should apply)</span>"
        }
        elseif ($svnStatus.RebootPending) {
            $svnIcon  = Format-CardIcon -Type 'sync' -Color '#F59E0B' -Format $Format
            $svnLabel = 'Pending SVN reboot - firmware SVN update not yet applied'
        }
        elseif ($svnStatus.RevocationAppliedPendingReboot) {
            $svnIcon  = Format-CardIcon -Type 'sync' -Color '#F59E0B' -Format $Format
            $svnLabel = '2011 CA revocation pending reboot'
        }
        elseif ($svnStatus.RevocationPending) {
            $svnIcon  = Format-CardIcon -Type 'info' -Color '#3B82F6' -Format $Format
            $svnLabel = '2011 CA not yet revoked'
        }
        else {
            $svnIcon  = Format-CardIcon -Type 'warning' -Color '#5BC0DE' -Format $Format
            $svnLabel = $svnStatus.ComplianceStatus
        }
        $parts = @("$svnIcon $svnLabel")
        # SVN version details - identical shape on every stage.
        #   Cmdlet-conventional trio (Firmware / Boot Manager / Staged):
        #     Firmware SVN     - raw-DBX BootMgr max (canonical, bug-free vs PS#27058)
        #     Boot Manager SVN - cmdlet-only (on-disk boot manager binary; 'N/A' if KB5077241 absent)
        #     Staged SVN       - raw-DBX of DBXUpdateSVN.bin BootMgr (canonical)
        #   Always-raw additional components (CdBoot / WdsMgr): the two other SVN-keyed
        #   entries that live in the DBX alongside BootMgr but aren't surfaced by the
        #   cmdlet. Useful as a parity readout when only the BootMgr value moves, and
        #   for verifying SVN Order cross-checks at a glance.
        $parts += "Firmware SVN: $($svnStatus.FirmwareSVN)"
        $parts += "Boot Manager SVN: $($svnStatus.BootManagerSVN)"
        $parts += "Staged SVN: $($svnStatus.StagedSVN)"
        $parts += "CdBoot SVN: $($svnStatus.CdBootSVN)"
        $parts += "WdsMgr SVN: $($svnStatus.WdsMgrSVN)"
        # SVN update pending
        if ($svnStatus.SvnUpdatePending) {
            $pendIcon = Format-CardIcon -Type 'clock' -Color '#F59E0B' -Format $Format
            $parts += "$pendIcon SVN update pending (DBXUpdateSVN.bin $($svnStatus.WindowsUpdateSVN) not yet in DBX)"
        }
        # Stage
        if ($null -ne $svnStatus.Stage) {
            $stagePR = $svnStatus.StageDetail -match 'pending SVN reboot'
            $stageIcon = switch ($svnStatus.Stage) {
                'Stage 4'   { Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format }
                'Stage 3+4' { Format-CardIcon -Type 'sync' -Color '#F59E0B' -Format $Format }
                'Stage 3'   { if ($stagePR) { Format-CardIcon -Type 'sync' -Color '#F59E0B' -Format $Format } else { Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format } }
                'Stage 2'   { Format-CardIcon -Type 'clock' -Color '#3B82F6' -Format $Format }
                default     { Format-CardIcon -Type 'clock' -Color '#6B7280' -Format $Format }
            }
            $parts += "$stageIcon $($svnStatus.Stage): $($svnStatus.StageDetail)"
        }
        # Enforcement overview - always shown as a playbook status of where each mitigation stands
        $enfSvnReboot = ($null -ne $svnStatus -and $svnStatus.RebootPending)
        $enfRevocReboot = ($null -ne $svnStatus -and $svnStatus.RevocationAppliedPendingReboot)
        # Mode indicator
        if ($EnforceSvnCompliance -eq 'Enforce SVN') {
            $modeIcon = Format-CardIcon -Type 'cog' -Color '#3B82F6' -Format $Format
            $parts += "$modeIcon Enforcement: Active"
            if ($enforceMissingOptIn) {
                $warnIcon = Format-CardIcon -Type 'warning' -Color '#F59E0B' -Format $Format
                $parts += "$warnIcon <span style='color:#F59E0B;'>WU opt-in not enabled. Set securebootAction to &quot;Enable opt-in&quot; for full deployment</span>"
            }
        }
        elseif ($EnforceSvnCompliance -eq 'Passive') {
            $eyeIcon = Format-CardIcon -Type 'eye' -Color '#6B7280' -Format $Format
            $parts += "$eyeIcon Enforcement: Passive (June 2026 - 2027) <span style=`"font-size:0.85em; color:#888;`">(last run)</span>"
        }
        else {
            $eyeIcon = Format-CardIcon -Type 'eye' -Color '#6B7280' -Format $Format
            $parts += "$eyeIcon Enforcement: Not configured (MS enforcement: June 2026 - 2027)"
        }
        $parts += '<b>SVN Enforcement</b>'
        if ($null -ne $svnEnforcementResult) {
            # Active enforcement just ran - use its results
            $parts += Build-EnforcementMitigationLines -Format $Format -EnfResult $svnEnforcementResult -SvnRebootPending $enfSvnReboot -RevocationRebootPending $enfRevocReboot -SvnPendingUpdate $svnPendingUpdate -SvnPendingUpdateComponents $svnPendingNames -SvnNotApplied $svnNotApplied -SvnNotAppliedComponents $svnNotAppliedComps
        }
        else {
            # Build ground-truth status from available signals
            $has1799 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1799)
            $has1808 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1808)
            $has1037 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1037)
            $has1042 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1042)
            $pca2011Revoked = ($ca2011RevokedInDbx.Count -gt 0)
            $svnInDbx = ($null -ne $svnStatus.DbxSVN -and $svnStatus.DbxSVN -ne 0 -and $svnStatus.DbxSVN -ne '0.0')
            $rebootPending = ($null -ne $certStatus -and $certStatus.EventId -eq 1800)
            $bootMgrConfirmed = ($has1799 -or $has1808 -or ($null -ne $servicingStatus -and $servicingStatus.WindowsUEFICA2023Capable -ge 2))
            # Detect if stages 3+4 were pushed ahead of Microsoft's enforcement deadline
            $msEnforcementDate = [datetime]'2026-06-24'
            $ev1037 = Get-LatestSecureBootEvent -CertStatus $certStatus -EventId 1037
            $ev1042 = Get-LatestSecureBootEvent -CertStatus $certStatus -EventId 1042
            $previouslyEnforced = (($null -ne $ev1037 -and $ev1037.Time -lt $msEnforcementDate) -or
                                   ($null -ne $ev1042 -and $ev1042.Time -lt $msEnforcementDate))
            if ($previouslyEnforced) {
                $piIcon = Format-CardIcon -Type 'info' -Color '#5BC0DE' -Format $Format
                $parts += "&nbsp;&nbsp;&nbsp;&nbsp;<span style='color:#5BC0DE;'>$piIcon Previously enforced (ahead of schedule)</span>"
            }
            # Build a virtual enforcement result for consistent rendering
            $groundTruth = @{
                Mitigation1             = if ($has2023InDb) { 'AlreadyApplied' }
                                          else { $null }
                Mitigation2             = if ($bootMgrConfirmed) { 'AlreadyApplied' }
                                          elseif ($has2023InDb -and $rebootPending) { 'Applied' }
                                          else { $null }
                Mitigation3             = if ($pca2011Revoked -or $has1037) { 'AlreadyApplied' } else { $null }
                Mitigation4             = if ($svnInDbx -or $has1042) { 'AlreadyApplied' } else { $null }
                Mitigation1BlockedReason = $null
                Mitigation2BlockedReason = $null
                Mitigation3BlockedReason = $null
                Mitigation4BlockedReason = $null
                RebootRequired          = $rebootPending
            }
            $parts += Build-EnforcementMitigationLines -Format $Format -EnfResult $groundTruth -SvnRebootPending $enfSvnReboot -RevocationRebootPending $enfRevocReboot -SvnPendingUpdate $svnPendingUpdate -SvnPendingUpdateComponents $svnPendingNames -SvnNotApplied $svnNotApplied -SvnNotAppliedComponents $svnNotAppliedComps
        }
        return Join-CardLines -Lines $parts -Format $Format
    }
    
    # Helper function: Build DBX validation section (firmware DBX vs staged DBX .bin files).
    # Answers the actionable question "did the Secure-Boot-Update scheduled task commit
    # what Windows servicing staged?" Takes the pre-computed Compare-DbxAgainstStagedBins
    # result so the Html (Ninja) and Local paths share one source of truth.
    function Build-DbxValidationSection {
        param (
            [string]$Format,
            $Result              # The Compare-DbxAgainstStagedBins result object (must have .Succeeded)
        )
        if ($null -eq $Result -or -not $Result.Succeeded) { return $null }
        
        $fileCount = [int]$Result.FilesScanned
        $fileWord  = if ($fileCount -eq 1) { 'file' } else { 'files' }
        $supCount  = [int]$Result.SupersededCount
        $supSuffix = if ($supCount -gt 0) { " <span style='color:#888;'>(+ $supCount superseded by SVN)</span>" } else { '' }
        
        # All-clean path: scheduled task has committed every staged signature (or live SVN
        # supersedes the rest). Green check only; no breakdown needed.
        if ($Result.MissingCount -eq 0) {
            $chk = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            return "$chk Staged DBX fully applied ($($Result.MatchedCount) matched across $fileCount $fileWord)$supSuffix"
        }
        
        # Gap path: headline count + per-file breakdown so operators see which staged .bin
        # didn't land. Per-file counts are informational - the authoritative MissingCount
        # is already de-duplicated across files, so per-file tallies may sum higher.
        $warn = Format-CardIcon -Type 'warning' -Color '#F0AD4E' -Format $Format
        $headline = "<span style='color:#F0AD4E;'>$warn $($Result.MissingCount) of $($Result.RequiredCount) staged DBX signatures not yet applied</span>$supSuffix"
        
        # SVN-component callout: when any of the three boot-component SVN entries (BootMgr /
        # CdBoot / WdsMgr) didn't absorb, surface them directly below the headline so the
        # staged-vs-firmware SVN pair is visible without expanding the per-file breakdown.
        # The SVN Compliance card section classifies which state this represents:
        #   * All 3 missing, firmware has no prior SVN      -> pre-rollout (Stage 1/2)
        #   * All 3 missing, firmware has prior SVN entries -> pre-reboot (Stage 3/4 bump)
        #   * 1-2 missing, every missing has prior SVN      -> benign pending SVN update
        #   * 1-2 missing, at least one missing is absent   -> true partial-commit rejection
        # The callout itself stays neutral ("staged X, raw firmware Y") - it's the factual
        # pair that lets the reader reconcile with the card-level label above.
        #
        # Pre-rollout reassurance: on Stage 1/2 devices firmware has zero SVN entries,
        # so every SVN-component sig (typically 3 across DBXUpdateSVN.bin +
        # DBXUpdateSVNLegacy.bin) shows as missing even though nothing is wrong -
        # Microsoft simply hasn't pushed the revocation yet (rollout: June 2026 - 2027).
        # Detect this specific pattern (every missing SVN component has no firmware SVN)
        # and swap the alarming per-component callout for a single reassuring notice so
        # operators don't chase it. Non-SVN hash misses (if any) are independent and
        # still surface under their own per-file row as "N/M matched, X missing" - the
        # gate used to also require $missingComponents.Count == $MissingCount, which
        # incorrectly dropped the pre-rollout reassurance whenever even a single
        # unrelated hash sig was missing alongside the SVN entries.
        $componentCallout = ''
        $missingComponents = @($Result.MissingComponents)
        $isPreRollout = $false
        if ($missingComponents.Count -gt 0) {
            $noFirmwareSvnAtAll = (@($missingComponents | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.FirmwareSvn) }).Count -eq 0)
            $isPreRollout       = $noFirmwareSvnAtAll
            
            if ($isPreRollout) {
                $infoIcon = Format-CardIcon -Type 'info' -Color '#3B82F6' -Format $Format
                $compNames = @($missingComponents | ForEach-Object { $_.Component }) -join ' / '
                # padding-left:24px aligns the notice text under the <details> disclosure
                # triangle below, matching the visual layout of the component callout.
                $componentCallout =
                    "<div style='padding-left:24px;margin-top:4px;font-size:0.90em;color:#888;'>" +
                    "$infoIcon These are SVN firmware revocations ($compNames). <br />" +
                    "Firmware has not yet applied any SVN entries. Expected pre-rollout state. <br />" +
                    "Awaiting Microsoft enforcement (June 2026 - 2027)." +
                    '</div>'
            }
            else {
                $compLines = New-Object System.Collections.Generic.List[string]
                foreach ($mc in $missingComponents) {
                    $comp = [System.Net.WebUtility]::HtmlEncode([string]$mc.Component)
                    $req  = if ([string]::IsNullOrWhiteSpace([string]$mc.RequiredSvn)) { 'n/a' } else { [string]$mc.RequiredSvn }
                    $fw   = if ([string]::IsNullOrWhiteSpace([string]$mc.FirmwareSvn)) { 'absent' } else { [string]$mc.FirmwareSvn }
                    $compLines.Add("<b>$comp SVN</b>: staged <b>$req</b>, raw firmware <b>$fw</b>") | Out-Null
                }
                # padding-left matches the <details> wrapper below (also 24px) so the callout
                # text sits directly beneath the disclosure triangle.
                $componentCallout = "<div style='padding-left:24px;margin-top:4px;font-size:0.95em;'>" + (($compLines) -join '<br />') + '</div>'
            }
        }
        
        $perFile = @($Result.PerFile)
        if ($perFile.Count -eq 0) {
            $lines = @($headline)
            if ($componentCallout) { $lines += $componentCallout }
            return Join-CardLines -Lines $lines -Format $Format
        }
        
        $rowsHtml = New-Object System.Collections.Generic.List[string]
        foreach ($pf in $perFile) {
            $name = [System.Net.WebUtility]::HtmlEncode([string]$pf.Name)
            $req  = [int]$pf.Required
            $mat  = [int]$pf.Matched
            $mis  = [int]$pf.Missing
            $sup  = [int]$pf.Superseded
            $supPart = if ($sup -gt 0) { ", $sup superseded" } else { '' }
            $rowsHtml.Add("&nbsp;&nbsp;&bull; <b>$name</b>: $mat/$req matched, $mis missing$supPart") | Out-Null
            # Per-file sub-rows naming each missing SVN component. Skip hash-only .bin files
            # (dbxupdate.bin etc.) - their missing entries are already tallied in the count,
            # and hash-level detail isn't actionable at the card level.
            $md = @($pf.MissingDetails)
            foreach ($m in $md) {
                if ([string]::IsNullOrWhiteSpace([string]$m.Component)) { continue }
                # Pre-rollout: suppress the alarming "staged X, raw firmware absent" sub-rows.
                # The reassuring callout above already explains every SVN-component miss as
                # expected pre-enforcement state; the raw sub-rows would contradict it.
                if ($isPreRollout) { continue }
                $comp = [System.Net.WebUtility]::HtmlEncode([string]$m.Component)
                $r    = if ([string]::IsNullOrWhiteSpace([string]$m.RequiredSvn)) { 'n/a' } else { [string]$m.RequiredSvn }
                $f    = if ([string]::IsNullOrWhiteSpace([string]$m.FirmwareSvn)) { 'absent' } else { [string]$m.FirmwareSvn }
                $rowsHtml.Add("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- missing: <b>$comp</b> (staged $r, raw firmware $f)") | Out-Null
            }
        }
        
        $detailsInner = "<div style='margin-top:6px;'>" + (($rowsHtml) -join '<br />') + '</div>'
        # Ninja strips inline styles on <details>/<summary> but honors them on <div>. Wrap the
        # whole disclosure element in a padded div so the triangle + summary + expanded rows
        # all shift together, visually nesting under the headline.
        $details = "<div style='padding-left:24px;'><details><summary style='cursor:pointer;'>Breakdown by staged file</summary>$detailsInner</details></div>"
        
        $lines = @($headline)
        if ($componentCallout) { $lines += $componentCallout }
        $lines += $details
        return Join-CardLines -Lines $lines -Format $Format
    }
    
    # Helper function: Build boot media section (outdated PCA-2011-signed bootable USB/CD).
    # Takes the pre-computed Test-BootMediaPca2023 result so the scan runs once per execution
    # and the Html (Ninja) and Local paths share one rendering.
    function Build-BootMediaSection {
        param (
            [string]$Format,
            $Result              # The Test-BootMediaPca2023 result (must have .Outdated collection)
        )
        if ($null -eq $Result -or $Result.Outdated.Count -eq 0) { return $null }
        $warn = Format-CardIcon -Type 'warning' -Color '#D9534F' -Format $Format
        $kbLink = '<a href="https://support.microsoft.com/en-us/topic/updating-windows-bootable-media-to-use-the-pca2023-signed-boot-manager-d4064779-0e4e-43ac-b2ce-24f434fcfa0f" target="_blank" rel="nofollow noopener noreferrer">MS KB: Updating bootable media</a>'
        $mLines = @("<span style='color:#D9534F;'>$warn Outdated (PCA 2011-signed) boot media detected:</span>")
        foreach ($item in $Result.Outdated) {
            $mLines += "&nbsp;&nbsp;&bull; $($item.Drive)\$($item.File) - $($item.SignedBy)"
        }
        $mLines += "<span style='font-size:0.9em;'>$kbLink</span>"
        return Join-CardLines -Lines $mLines -Format $Format
    }
    
    # Helper function: Build KEK update availability section (vendor-signed KEK 2023 update lookup).
    # Takes the pre-computed Get-KekUpdateAvailability result so the lookup runs once per execution.
    function Build-KekUpdateAvailabilitySection {
        param (
            [string]$Format,
            $Result              # The Get-KekUpdateAvailability result (must have .Succeeded + .Available)
        )
        if ($null -eq $Result -or -not $Result.Succeeded -or -not $Result.Available) { return $null }
        $warn = Format-CardIcon -Type 'info' -Color '#F0AD4E' -Format $Format
        $vendorLine = if ($Result.Vendors.Count -gt 0) { ': ' + ($Result.Vendors -join ', ') } else { '' }
        return "<span style='color:#F0AD4E;'>$warn KEK 2023 update available from vendor$vendorLine</span>"
    }
    
    # Helper function: Build rollout tier / bucket section for card display
    function Build-RolloutTierSection {
        param ([string]$Format)
        $confValue = ($certStatus.Confidence).ToString().Trim()
        Write-Log "INFO" "Rollout Tier: confValue='$confValue' (length=$($confValue.Length))"
        # the array seems to be missing, but the lenght check is a catch all
        if ($confValue -in @('0', 'U', 'N', '') -or $confValue.Length -le 1 -or $confValue -match 'Under Observation|More Data Needed|No Data Observed|Action Required') {
            $content = "<span style='color:#888;'>Under Observation - More Data Needed</span>"
        }
        else {
            $confItems = $confValue -split ',\s*' | ForEach-Object { ($_ -replace '^3P\s+', '').Trim() }
            $confColor = switch -Wildcard ($confValue) { '*High*' { '#26A644' }; '*Action*' { '#D9534F' }; default { '#5BC0DE' } }
            if ($confItems.Count -gt 1) {
                $confLines = @()
                for ($i = 0; $i -lt $confItems.Count; $i++) {
                    $confLines += "&nbsp;&nbsp;&nbsp;&nbsp;$($i + 1). $($confItems[$i])"
                }
                $joined = Join-CardLines -Lines $confLines -Format $Format
                $content = "<span style='color:$confColor;'>$joined</span>"
            }
            else {
                $content = "<span style='color:$confColor;'>$($confItems[0])</span>"
            }
        }
        if ($null -ne $certStatus.SkipReason) {
            $warnIcon = Format-CardIcon -Type 'warning' -Color '#D9534F' -Format $Format
            $content += " &nbsp;$warnIcon $($certStatus.SkipReason)"
        }
        return $content
    }
    
    # Helper function: Build update task section for card display
    function Build-UpdateTaskSection {
        param ([string]$Format)
        if ($scheduledTaskPresent) {
            $icon = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            return "$icon Secure-Boot-Update task present"
        }
        else {
            $icon = Format-CardIcon -Type 'warning' -Color '#D9534F' -Format $Format
            return "$icon Secure-Boot-Update task missing"
        }
    }
    
    # Helper function: Build opt-in status section for card display
    function Build-OptInSection {
        param ([string]$Format)
        $parts = @()
        switch ($optInStatus.Summary) {
            'Enabled'     { $parts += "$(Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format) WU Secure Boot management enabled" }
            'Blocked'     { $parts += "$(Format-CardIcon -Type 'warning' -Color '#F0AD4E' -Format $Format) Opted in but telemetry too low (AllowTelemetry=0)" }
            'Not enabled' { $parts += "$(Format-CardIcon -Type 'info' -Color '#6C757D' -Format $Format) WU Secure Boot management not enabled" }
        }
        if ($null -ne $optInStatus.HighConfidenceOptOut -and $optInStatus.HighConfidenceOptOut -ne 0) {
            $parts += "$(Format-CardIcon -Type 'ban' -Color '#D9534F' -Format $Format) HighConfidenceOptOut is set"
        }
        if ($optInStatus.AvailableUpdatesPolicySet) {
            $apHex = '0x{0:X}' -f $optInStatus.AvailableUpdatesPolicy
            $parts += "$(Format-CardIcon -Type 'building' -Color '#5BC0DE' -Format $Format) AvailableUpdatesPolicy: $apHex (GPO/MDM)"
        }
        return Join-CardLines -Lines $parts -Format $Format
    }
    
    # Helper function: Build event log summary section for card display
    function Build-EventLogSection {
        param ([string]$Format)
        $eventColorMap = @{
            1808 = '#26A644'; 1799 = '#26A644'; 1037 = '#26A644'; 1042 = '#26A644'
            1801 = '#F0AD4E'; 1800 = '#F0AD4E'
            1032 = '#D9534F'; 1033 = '#D9534F'; 1795 = '#D9534F'; 1796 = '#D9534F'
            1797 = '#D9534F'; 1798 = '#D9534F'; 1802 = '#D9534F'; 1803 = '#D9534F'
        }
        $lines = @()
        foreach ($entry in ($certStatus.EventSummary | Sort-Object LastSeen)) {
            $timeStr = $entry.LastSeen.ToString('yyyy-MM-dd HH:mm')
            $color = if ($eventColorMap.ContainsKey($entry.Id)) { $eventColorMap[$entry.Id] } else { '#5BC0DE' }
            $lines += "<span style='color:$color;'>$timeStr &nbsp; [$($entry.Id)] $($entry.Description) ($($entry.Count)x)</span>"
        }
        # Reboot correlation annotation
        if ($null -ne $certStatus.RebootCorrelation) {
            $rc = $certStatus.RebootCorrelation
            if ($rc.Confirmed) {
                $bootTimeStr = $rc.BootTimes[-1].ToString('yyyy-MM-dd HH:mm')
                $syncIcon = Format-CardIcon -Type 'sync' -Color '#5BC0DE' -Format $Format
                $lines += "<span style='color:#5BC0DE;'>&nbsp;&nbsp;&nbsp;$syncIcon Reboot at $bootTimeStr bridged 1800 &rarr; 1799</span>"
            }
            else {
                $qIcon = Format-CardIcon -Type 'question' -Color '#F0AD4E' -Format $Format
                $lines += "<span style='color:#F0AD4E;'>&nbsp;&nbsp;&nbsp;$qIcon 1800 &rarr; 1799 detected but no reboot found between them</span>"
            }
        }
        # 1799 pending-1808 note
        if ($pending1808Note) {
            $iIcon = Format-CardIcon -Type 'info' -Color '#5BC0DE' -Format $Format
            $lines += "<span style='color:#5BC0DE;'>&nbsp;&nbsp;&nbsp;$iIcon 1808 expected on next scheduled task cycle</span>"
        }
        return Join-CardLines -Lines $lines -Format $Format
    }
    
    # Hypervisor SignatureOwner GUIDs - PK entries signed with these owners but no cert payload
    # identify the device as a VM guest where Secure Boot cert rotation is hypervisor-managed.
    # Reference: garlin's Check_UEFI-CA2023.ps1 (https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates).
    $script:HYPERVISOR_OWNER_GUIDS = @{
        'a3d5e95b-0a8f-4753-8735-445afb708f62' = 'VMware'
    }
    
    # Helper function: Parse UEFI signature database (db/dbx) for X509 certificates
    # May emit synthetic PSCustomObject entries (with .Subject and .Hypervisor) for hypervisor-owned
    # signatures with empty certificate payload (e.g. VMware PK).
    function Parse-UefiSignatureDatabase {
        param (
            [byte[]]$Bytes
        )
        
        $certs = @()
        $X509_GUID = [Guid]::new("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
        
        # Strip optional authenticode signature wrapper (ASN.1 SEQUENCE header)
        # Some firmware prepends a DER signature to the EFI_SIGNATURE_LIST payload.
        # garlin's reference implementations detect this at offset 40.
        $offset = 0
        if ($Bytes.Length -gt 44 -and $Bytes[40] -eq 0x30 -and $Bytes[41] -eq 0x82) {
            $sigLength = $Bytes[42] * 256 + $Bytes[43] + 4
            if ($sigLength -lt $Bytes.Length) {
                Write-Log "INFO" "Stripping $sigLength-byte authenticode signature wrapper from UEFI variable"
                $Bytes = [byte[]]$Bytes[$sigLength..($Bytes.Length - 1)]
            }
        }
        
        while ($offset -lt $Bytes.Length) {
            $start = $offset
            $guidBytes = [byte[]]$Bytes[$offset..($offset + 15)]
            if ($guidBytes.Length -ne 16) {
                Write-Log "WARNING" "Invalid GUID length at offset $($offset): $($guidBytes.Length)"
                break
            }
            $guid = [Guid]::new($guidBytes)
            $offset += 16
            
            $listSize = [BitConverter]::ToUInt32($Bytes, $offset)
            $offset += 4
            
            $headerSize = [BitConverter]::ToUInt32($Bytes, $offset)
            $offset += 4
            
            $sigSize = [BitConverter]::ToUInt32($Bytes, $offset)
            $offset += 4
            
            if ($guid -ne $X509_GUID) {
                # Skip non-X509 lists
                $offset = $start + $listSize
                continue
            }
            
            # Skip header (usually 0)
            $offset += $headerSize
            
            # Calculate number of signatures
            $remaining = $listSize - 28 - $headerSize
            if ($remaining -lt 0 -or ($remaining % $sigSize -ne 0 -and $sigSize -ne 0)) {
                Write-Log "WARNING" "Invalid signature list size at offset $($start): remaining=$remaining, sigSize=$sigSize"
                $offset = $start + $listSize
                continue
            }
            $numSigs = if ($sigSize -eq 0) { 0 } else { $remaining / $sigSize }
            
            for ($i = 0; $i -lt $numSigs; $i++) {
                $sigBytes = [byte[]]$Bytes[$offset..($offset + $sigSize - 1)]
                $offset += $sigSize
                
                # EFI_SIGNATURE_DATA: GUID (16 bytes) + cert data
                if ($sigBytes.Length -lt 16) {
                    Write-Log "WARNING" "Signature data too short at offset $($offset - $sigSize): Length $($sigBytes.Length)"
                    continue
                }
                $ownerGuidBytes = [byte[]]$sigBytes[0..15]
                $ownerGuid = [Guid]::new($ownerGuidBytes)
                
                # Hypervisor PK detection: X509 signature list with a known hypervisor owner GUID
                # and empty cert payload - emit a synthetic entry so downstream code can route to
                # the Virtualized state rather than treating this as a parse failure.
                $ownerKey = $ownerGuid.ToString()
                if ($sigBytes.Length -le 16 -and $script:HYPERVISOR_OWNER_GUIDS.ContainsKey($ownerKey)) {
                    $hv = $script:HYPERVISOR_OWNER_GUIDS[$ownerKey]
                    Write-Log "INFO" "Detected $hv hypervisor PK (SignatureOwner $ownerKey with no certificate payload)"
                    $synthetic = [PSCustomObject]@{
                        Subject    = "CN=$hv Virtual Machine Platform Key"
                        NotBefore  = [DateTime]::MinValue
                        NotAfter   = [DateTime]::MaxValue
                        Hypervisor = $hv
                        Thumbprint = $null
                    }
                    $certs += $synthetic
                    continue
                }
                
                $certBytes = [byte[]]$sigBytes[16..($sigBytes.Length - 1)]
                
                try {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certBytes)
                    $certs += $cert
                }
                catch {
                    Write-Log "WARNING" "Failed to parse certificate at offset $($offset - $sigSize): $($_.Exception.Message)"
                }
            }
        }
        
        return $certs
    }
    
    # Capability detection: KB5077241 (Feb 2025) added Get-SecureBootSVN and -Decoded parameter
    $script:HasDecodedParam = $false
    $script:HasSVNCmdlet    = $false
    try {
        $decodedParam = (Get-Command Get-SecureBootUEFI -ErrorAction Stop).Parameters.ContainsKey('Decoded')
        $script:HasDecodedParam = $decodedParam
    }
    catch { }
    try {
        $null = Get-Command Get-SecureBootSVN -ErrorAction Stop
        $script:HasSVNCmdlet = $true
    }
    catch { }
    if ($script:HasDecodedParam) { Write-Log  "INFO" "Get-SecureBootUEFI -Decoded parameter available (KB5077241+)" }
    if ($script:HasSVNCmdlet)    { Write-Log "INFO" "Get-SecureBootSVN cmdlet available (KB5077241+)" }
    
    # --- SVN (Security Version Number) functions ---
    # SVN tracks boot component revocation levels stored as EFI_CERT_SHA256_GUID entries in UEFI DBX.
    # Introduced with the Feb 2025 Secure Boot hardening rollout (KB5046714 -> KB5077241):
    #   Stage 1 (May 2024)  : 2023 certs added to db via Windows Update
    #   Stage 2 (Feb 2025)  : 2023 boot manager deployed, Get-SecureBootSVN cmdlet added (KB5077241)
    #   Stage 3 (est. 2026) : PCA 2011 revoked in dbx, SVN enforcement begins
    #   Stage 4 (est. 2027) : Full enforcement - 2011 certs removed from db
    # SVN progression: 0.0 (none) -> 2.0 (PCA 2011 revoked via DBXUpdate2024.bin) -> 7.0 (via DBXUpdateSVN.bin)
    # GUID prefixes for BootMgr, CDBoot, WDSMgr EFI files
    # Source: https://github.com/microsoft/secureboot_objects/blob/main/Archived/dbx_info_msft_4_09_24_svns.csv
    $script:EFI_BOOTMGR_DBXSVN_GUID = '01612B139DD5598843AB1C185C3CB2EB92'
    $script:EFI_CDBOOT_DBXSVN_GUID  = '019D2EF8E827E15841A4884C18ABE2F284'
    $script:EFI_WDSMGR_DBXSVN_GUID  = '01C2CA99C9FE7F6F4981279E2A8A535976'
    # SHA256 signature type GUID for raw byte parsing
    $script:EFI_CERT_SHA256_GUID = [Guid]::new("c1c41626-504c-4092-aca9-41f936934328")
    
    # Per-component SVN compliance floor for the current Microsoft rollout phase.
    # A device whose firmware SVN for a given component is >= the floor below is
    # considered compliant for the active enforcement window, regardless of what
    # SVN the staged DBXUpdateSVN.bin happens to contain. Microsoft sometimes
    # bumps the staged file's SVN ahead of any actual enforcement change (e.g.,
    # the staged file ships 8.0 while Stage 4 enforcement still targets 7.0), and
    # a device at the prior level is not "behind" - it is at the enforcement target.
    #
    # Distinguishes the two staged .bin sources:
    #   DBXUpdate2024.bin    - bumps BootMgr SVN to 2.0 + revokes Production CA 2011
    #   DBXUpdateSVN.bin     - bumps BootMgr SVN to the current rollout target (7.0)
    # Without this floor the classifier would compare staged-vs-firmware byte SVNs
    # directly, which produces a false "SVN Update Not Applied" callout the moment
    # Microsoft pushes a newer-than-enforcement-target SVN into the staged file.
    #
    # Bump these values as their SVNs increase.
    # Last SVN iteration check: 9.0 - June 2026
    $script:SVN_COMPLIANCE_FLOORS = @{
        BootMgr = '8.0'
        CdBoot  = '3.0'
        WdsMgr  = '3.0'
    }
    
    # Extract SVN version (major.minor) from a hex signature data string.
    # Sources:
    #   - https://github.com/microsoft/secureboot_objects/blob/main/scripts/utility_functions.py
    #   - https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates/commit/d356e1645d14440f1113dbd31a78ff374c19e1ef
    #
    # The two SVN uint16 fields are stored LITTLE-ENDIAN in the signature data, NOT
    # big-endian as garlin's original SVN_Order.ps1 (and earlier revisions of this
    # script) assumed. Byte layout in the post-owner hex string:
    #   hex 32-33 : signature type byte (0x01)
    #   hex 34-35 : minor low byte
    #   hex 36-37 : minor high byte
    #   hex 38-39 : major low byte
    #   hex 40-41 : major high byte
    # To rebuild each uint16 we concatenate <high><low> in that order before passing
    # to ToUInt16(.., 16), which parses big-endian. The result is the actual little-
    # endian value the firmware wrote.
    #
    # The bug was dormant on every SVN currently shipped (major < 256, minor == 0):
    # the high byte of major sat at hex 40-41 == 0x00 and the original big-endian
    # read of hex 36-39 happened to produce the right number because hex 36-37
    # (real minor low byte) was also 0x00. The fix lands BEFORE Microsoft pushes
    # any SVN with a non-zero minor or a major >= 256.
    function Get-SignatureDataSVN {
        param ([string]$SignatureData)
        try {
            $major = [System.Convert]::ToUInt16($SignatureData.Substring(40,2) + $SignatureData.Substring(38,2), 16)
            $minor = [System.Convert]::ToUInt16($SignatureData.Substring(36,2) + $SignatureData.Substring(34,2), 16)
            return '{0}.{1}' -f $major, $minor
        }
        catch { return $null }
    }
    
    # Read all SHA256 signature hex strings from raw UEFI database bytes
    function Get-DbxSignatureData {
        param ([byte[]]$Bytes)
        $sigDataList = @()
        $offset = 0
        while ($offset -lt $Bytes.Length) {
            $start = $offset
            if (($offset + 28) -gt $Bytes.Length) {
                break
            }
            $guidBytes = [byte[]]$Bytes[$offset..($offset + 15)]
            $guid = [Guid]::new($guidBytes)
            $offset += 16
            $listSize = [BitConverter]::ToUInt32($Bytes, $offset); $offset += 4
            $headerSize = [BitConverter]::ToUInt32($Bytes, $offset); $offset += 4
            $sigSize = [BitConverter]::ToUInt32($Bytes, $offset); $offset += 4
            if ($listSize -eq 0 -or ($start + $listSize) -gt $Bytes.Length) {
                break
            }
            if ($guid -ne $script:EFI_CERT_SHA256_GUID) {
                $offset = $start + $listSize
                continue
            }
            $offset += $headerSize
            $remaining = $listSize - 28 - $headerSize
            if ($remaining -le 0 -or $sigSize -eq 0) { $offset = $start + $listSize;
                continue
            }
            $numSigs = [math]::Floor($remaining / $sigSize)
            for ($i = 0; $i -lt $numSigs; $i++) {
                if (($offset + $sigSize) -gt $Bytes.Length) {
                    break
                }
                $sigBytes = [byte[]]$Bytes[$offset..($offset + $sigSize - 1)]
                $offset += $sigSize
                # Skip first 16 bytes (SignatureOwner GUID), output only the hash data
                # Matches garlin's format: SignatureDataBytes[0x10..0x2F]
                # Source: https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates
                if ($sigBytes.Length -gt 16) {
                    $hashBytes = [byte[]]$sigBytes[16..($sigBytes.Length - 1)]
                    $hexStr = ($hashBytes | ForEach-Object { $_.ToString('X2') }) -join ''
                    $sigDataList += $hexStr
                }
            }
        }
        return $sigDataList
    }
    
    # Single canonical raw-DBX SVN parser. Returns an ordered map of the three SVN-keyed
    # boot components (BootMgr / CdBoot / WdsMgr) -> max SVN string ("X.Y") or $null when
    # absent. Single source of truth for raw-byte SVN extraction across the script;
    # consumed by Get-DbxBootMgrSVN, Compare-DbxAgainstStagedBins, and Get-SecureBootSVNStatus
    # so the parsing path is identical wherever an SVN value originates.
    #
    # IMPORTANT: explicit max-by-parsed-version. Microsoft's pushed Get-SecureBootSVN
    # cmdlet has an open bug (PowerShell/PowerShell#27058). It reports whichever matching
    # entry appears LAST in DBX order rather than the MAX, so a fleet with DBX SVN 7.0
    # followed by 0.0/2.0 entries silently reports 2.0. Lex-sort happens to work today
    # because SVN bytes sit at a fixed hex offset and trailing bytes are stable, but it
    # is one firmware quirk away from the same failure mode. Parse every candidate,
    # keep the max.
    function Get-DbxComponentSVNs {
        param ([byte[]]$DbxBytes)
        $result = [ordered]@{
            BootMgr = $null
            CdBoot  = $null
            WdsMgr  = $null
        }
        if ($null -eq $DbxBytes -or $DbxBytes.Length -eq 0) { return $result }
        $guidMap = [ordered]@{
            BootMgr = $script:EFI_BOOTMGR_DBXSVN_GUID
            CdBoot  = $script:EFI_CDBOOT_DBXSVN_GUID
            WdsMgr  = $script:EFI_WDSMGR_DBXSVN_GUID
        }
        $sigData = @(Get-DbxSignatureData -Bytes $DbxBytes)
        foreach ($name in $guidMap.Keys) {
            $guid = $guidMap[$name]
            $candidates = @($sigData | Where-Object { $_ -match "^$guid" })
            if ($candidates.Count -eq 0) { continue }
            $maxVer = $null
            $maxStr = $null
            foreach ($c in $candidates) {
                $svn = Get-SignatureDataSVN $c
                if ([string]::IsNullOrWhiteSpace($svn)) { continue }
                try { $v = [version]$svn } catch { continue }
                if ($null -eq $maxVer -or $v -gt $maxVer) { $maxVer = $v; $maxStr = $svn }
            }
            if ($null -ne $maxStr) { $result[$name] = $maxStr }
        }
        return $result
    }
    
    # Thin convenience wrapper: BootMgr-only. Kept for call-site readability where only
    # the boot-manager component is needed (the historical primary signal the cmdlet
    # exposes via FirmwareSVN). Single source of truth lives in Get-DbxComponentSVNs.
    function Get-DbxBootMgrSVN {
        param ([byte[]]$DbxBytes)
        return (Get-DbxComponentSVNs -DbxBytes $DbxBytes).BootMgr
    }
    
    # Strip the authenticode/ASN.1 signed-header wrapper from a DBX .bin update file so
    # the downstream EFI_SIGNATURE_LIST parser sees the raw payload. The UEFI `dbx`
    # variable itself is already unwrapped, but .bin files staged by Windows servicing
    # (C:\Windows\System32\SecureBootUpdates\) carry a signed envelope. Detection logic
    # adapted from garlin's Get-UefiDatabaseSignatures: bytes[40..41] == 0x30 0x82 signals
    # an ASN.1 SEQUENCE with 2-byte length; the wrapper is 40 + (length-bytes + 4) bytes.
    # If the marker is absent, the file is already stripped and passed through unchanged.
    #
    # Source: https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates
    function Get-StrippedDbxBinBytes {
        param ([byte[]]$Bytes)
        if ($null -eq $Bytes -or $Bytes.Length -lt 44) { return $Bytes }
        if ($Bytes[40] -eq 0x30 -and $Bytes[41] -eq 0x82) {
            $sigLength = ($Bytes[42] * 256) + $Bytes[43] + 4
            $skip = 40 + $sigLength
            if ($skip -lt $Bytes.Length) {
                return [byte[]]$Bytes[$skip..($Bytes.Length - 1)]
            }
        }
        return $Bytes
    }
    
    # Compare firmware DBX against DBX .bin update files staged by Windows servicing.
    # Parses every dbx*.bin in C:\Windows\System32\SecureBootUpdates\ (where servicing
    # drops payloads for the Secure-Boot-Update scheduled task to apply) and reports
    # which staged signatures the firmware has absorbed. This answers the actionable
    # question "did servicing apply what it staged?" rather than comparing against
    # Microsoft's aspirational cumulative list.
    #
    # SVN-aware matching (adapted from garlin's Check_DBXUpdate.bin.ps1): if a staged
    # entry prefix-matches one of the three boot-component SVN GUIDs (BootMgr, CdBoot,
    # WdsMgr) AND firmware's live SVN for that GUID is >= the required SVN, count as
    # SUPERSEDED. Otherwise it's a real miss - Windows staged it and the scheduled
    # task hasn't successfully committed it to firmware yet.
    # Reference: garlin's Check_DBXUpdate.bin.ps1 (https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates)
    function Compare-DbxAgainstStagedBins {
        param (
            [byte[]]$DbxBytes,
            [string]$StagedPath = "$env:SystemRoot\System32\SecureBootUpdates"
        )
        $result = @{
            Succeeded         = $false
            FilesScanned      = 0
            FileNames         = @()
            RequiredCount     = 0
            MatchedCount      = 0
            MissingCount      = 0
            SupersededCount   = 0
            PerFile           = @()     # @{ Name; Required; Matched; Missing; Superseded; MissingDetails }
            MissingEntries    = @()     # @{ Hash; FromFiles; Component?; RequiredSvn?; FirmwareSvn? }
            MissingComponents = @()     # @{ Component; RequiredSvn; FirmwareSvn } - deduped across files
            LastChecked       = (Get-Date)
            Error             = $null
        }
        if ($null -eq $DbxBytes -or $DbxBytes.Length -eq 0) {
            $result.Error = 'DBX bytes not available'
            return $result
        }
        if (-not (Test-Path -LiteralPath $StagedPath)) {
            $result.Error = "Staged-updates folder not found: $StagedPath"
            return $result
        }
        $binFiles = @(
            Get-ChildItem -LiteralPath $StagedPath -Filter '*.bin' -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)dbx' }
        )
        if ($binFiles.Count -eq 0) {
            $result.Error = "No DBX .bin files in $StagedPath"
            return $result
        }
        
        # Firmware DBX hash set (uppercase hex).
        $dbxHashes = @{}
        foreach ($h in (Get-DbxSignatureData -Bytes $DbxBytes)) {
            if (-not [string]::IsNullOrWhiteSpace($h)) { $dbxHashes[$h.ToUpperInvariant()] = $true }
        }
        
        # GUID -> component-name map for missing-entry annotation and classification.
        # Matches the three boot-component SVN GUIDs defined at script scope. Name
        # choice mirrors Microsoft's naming in Get-SecureBootSVN.BootManagerSVN
        # (BootMgr/CdBoot/WdsMgr); kept short so card rows stay readable. Declared up
        # here (not next to the classify block) so the firmware-SVN lookup below can
        # iterate the same three GUIDs.
        $guidComponentMap = [ordered]@{
            $script:EFI_BOOTMGR_DBXSVN_GUID = 'BootMgr'
            $script:EFI_CDBOOT_DBXSVN_GUID  = 'CdBoot'
            $script:EFI_WDSMGR_DBXSVN_GUID  = 'WdsMgr'
        }
        
        # Firmware SVN levels for the three boot-component GUIDs, used to resolve
        # "missing" SVN-encoded entries against the live SVN instead of counting them as
        # gaps. Keyed by GUID prefix so the per-entry lookup in the match loop is O(1).
        # On pre-Stage-3/4 devices firmware has zero SVN entries, so this map stays
        # empty - downstream classify logic must NOT rely on iterating its keys to
        # identify components, otherwise pre-rollout devices never attribute a component
        # to their misses. Iterate $guidComponentMap.Keys for component identity.
        #
        # Sourced from the canonical Get-DbxComponentSVNs helper so the parsing path
        # matches Get-SecureBootSVNStatus / Get-DbxBootMgrSVN exactly.
        $componentSvnMap   = Get-DbxComponentSVNs -DbxBytes $DbxBytes
        $componentToGuid   = @{
            BootMgr = $script:EFI_BOOTMGR_DBXSVN_GUID
            CdBoot  = $script:EFI_CDBOOT_DBXSVN_GUID
            WdsMgr  = $script:EFI_WDSMGR_DBXSVN_GUID
        }
        $firmwareSvnByGuid = @{}
        foreach ($name in $componentSvnMap.Keys) {
            $svn = $componentSvnMap[$name]
            if ($null -ne $svn) { $firmwareSvnByGuid[$componentToGuid[$name]] = $svn }
        }
        
        # Per-file parse pass: parse each .bin, de-dupe within the file, store normalized
        # upper-hex sig list keyed by filename for the tallying pass below.
        $perFileSigs = [ordered]@{}
        foreach ($bf in $binFiles) {
            try {
                $raw = [IO.File]::ReadAllBytes($bf.FullName)
            }
            catch {
                Write-Log "WARNING" "Failed to read staged DBX file $($bf.Name): $($_.Exception.Message)"
                continue
            }
            $clean = Get-StrippedDbxBinBytes -Bytes $raw
            $sigs = @(Get-DbxSignatureData -Bytes $clean | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique)
            $perFileSigs[$bf.Name] = $sigs
        }
        
        # Shared matcher: returns a hashtable describing how one staged sig resolves
        # against firmware state. Status is 'matched' / 'superseded' / 'missing'.
        # For SVN-keyed sigs (those whose hash begins with one of the three boot-
        # component GUIDs), also attaches Component / RequiredSvn / FirmwareSvn so
        # the caller can render "missing: BootMgr (staged 8.0, raw firmware 2.0)" rows.
        # Iterates $guidComponentMap (static list of all three GUIDs) rather than
        # $firmwareSvnByGuid (which is empty on pre-Stage-3/4 devices) so component
        # identity is always resolved even when firmware has no prior SVN entries.
        #
        # Two distinct routes to 'superseded' for SVN-keyed entries:
        #   1) Firmware SVN >= staged SVN for this entry. Direct supersede - the
        #      staged sig is by definition obsolete because firmware already holds
        #      a newer revocation level for that component.
        #   2) Firmware SVN >= documented compliance floor for this rollout phase
        #      ($script:SVN_COMPLIANCE_FLOORS). Floor supersede - Microsoft has
        #      bumped the staged file's SVN ahead of the active enforcement target
        #      (e.g., staged 8.0 while Stage 4 enforces 7.0). A device at the prior
        #      level is at the enforcement target and must not be flagged as
        #      "SVN Update Not Applied". Without the floor check the
        #      classifier would generate a false partial-commit signal here.
        $classify = {
            param ($sig)
            $info = @{
                Status      = 'missing'
                Component   = $null
                RequiredSvn = $null
                FirmwareSvn = $null
            }
            if ($dbxHashes.ContainsKey($sig)) { $info.Status = 'matched'; return $info }
            foreach ($guid in $guidComponentMap.Keys) {
                if ($sig -match "^$guid") {
                    $info.Component   = $guidComponentMap[$guid]
                    $info.RequiredSvn = Get-SignatureDataSVN $sig
                    $info.FirmwareSvn = $firmwareSvnByGuid[$guid]   # may be null when firmware has no prior SVN for this GUID
                    if (-not [string]::IsNullOrWhiteSpace($info.FirmwareSvn)) {
                        try {
                            $fwVer = [version]$info.FirmwareSvn
                            if (-not [string]::IsNullOrWhiteSpace($info.RequiredSvn)) {
                                if ($fwVer -ge ([version]$info.RequiredSvn)) {
                                    $info.Status = 'superseded'
                                }
                            }
                            # Floor check (route 2). Only consult when route 1 did not
                            # already mark superseded. Compares firmware against the
                            # Enforcement target, SVN compliance version.
                            if ($info.Status -ne 'superseded') {
                                $floor = $script:SVN_COMPLIANCE_FLOORS[$info.Component]
                                if (-not [string]::IsNullOrWhiteSpace($floor)) {
                                    if ($fwVer -ge ([version]$floor)) {
                                        $info.Status = 'superseded'
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                    break
                }
            }
            return $info
        }
        
        # Per-file tally. Alongside running counts, collect the component names of
        # any missing SVN-keyed entries so the card can list which specific SVN
        # component (BootMgr / CdBoot / WdsMgr) didn't absorb - this is the clue
        # that distinguishes "pending reboot" from "firmware partial-commit failure".
        $perFileResults = New-Object System.Collections.Generic.List[hashtable]
        foreach ($name in $perFileSigs.Keys) {
            $fr = 0; $fm = 0; $fx = 0; $fs = 0
            $missingDetails = New-Object System.Collections.Generic.List[hashtable]
            foreach ($sig in $perFileSigs[$name]) {
                $fr++
                $c = & $classify $sig
                switch ($c.Status) {
                    'matched'    { $fm++ }
                    'superseded' { $fs++ }
                    default      {
                        $fx++
                        if (-not [string]::IsNullOrWhiteSpace($c.Component)) {
                            $missingDetails.Add(@{
                                Component   = $c.Component
                                RequiredSvn = $c.RequiredSvn
                                FirmwareSvn = $c.FirmwareSvn
                            }) | Out-Null
                        }
                    }
                }
            }
            $perFileResults.Add(@{
                Name           = $name
                Required       = $fr
                Matched        = $fm
                Missing        = $fx
                Superseded     = $fs
                MissingDetails = @($missingDetails)
            }) | Out-Null
        }
        
        # Global dedup tally. This is the authoritative figure (per-file counts double-count
        # a sig that lives in two .bin files). Track which file(s) each miss came from so
        # operators can see "DBXUpdate2024.bin has 3 sigs that never applied".
        $globalRequired = New-Object System.Collections.Generic.HashSet[string]
        $sigToFiles = @{}
        foreach ($name in $perFileSigs.Keys) {
            foreach ($sig in $perFileSigs[$name]) {
                [void]$globalRequired.Add($sig)
                if (-not $sigToFiles.ContainsKey($sig)) { $sigToFiles[$sig] = New-Object System.Collections.Generic.List[string] }
                [void]$sigToFiles[$sig].Add($name)
            }
        }
        
        $matched = 0; $missing = 0; $superseded = 0
        $missingEntries = New-Object System.Collections.Generic.List[hashtable]
        $missingComponents = New-Object System.Collections.Generic.List[hashtable]
        $seenComponents = @{}
        foreach ($sig in $globalRequired) {
            $c = & $classify $sig
            switch ($c.Status) {
                'matched'    { $matched++ }
                'superseded' { $superseded++ }
                default      {
                    $missing++
                    $missingEntries.Add(@{
                        Hash        = $sig
                        FromFiles   = @($sigToFiles[$sig])
                        Component   = $c.Component
                        RequiredSvn = $c.RequiredSvn
                        FirmwareSvn = $c.FirmwareSvn
                    }) | Out-Null
                    # Dedup global list of missing SVN components (across all files). A missed
                    # BootMgr SVN shows up in both DBXUpdateSVN.bin and its Legacy twin -
                    # operators only need to see the component once.
                    if (-not [string]::IsNullOrWhiteSpace($c.Component) -and -not $seenComponents.ContainsKey($c.Component)) {
                        $seenComponents[$c.Component] = $true
                        $missingComponents.Add(@{
                            Component   = $c.Component
                            RequiredSvn = $c.RequiredSvn
                            FirmwareSvn = $c.FirmwareSvn
                        }) | Out-Null
                    }
                }
            }
        }
        
        $result.Succeeded         = $true
        $result.FilesScanned      = $binFiles.Count
        $result.FileNames         = @($binFiles | ForEach-Object { $_.Name })
        $result.RequiredCount     = $globalRequired.Count
        $result.MatchedCount      = $matched
        $result.MissingCount      = $missing
        $result.SupersededCount   = $superseded
        $result.PerFile           = @($perFileResults)
        $result.MissingEntries    = @($missingEntries)
        $result.MissingComponents = @($missingComponents)
        return $result
    }
    
    # Boot media check: scan attached removable/optical volumes for PCA-2011-signed boot loaders.
    # When DBX revokes PCA 2011 (Stage 3), booting from such media would fail - so operators need
    # to know which drives must be refreshed. Returns structured volume list for card rendering.
    # Reference: garlin's Check_UEFI-CA2023.ps1 Check-BootManager (https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates).
    # MS guidance: https://support.microsoft.com/en-us/topic/updating-windows-bootable-media-to-use-the-pca2023-signed-boot-manager-d4064779-0e4e-43ac-b2ce-24f434fcfa0f
    function Test-BootMediaPca2023 {
        param (
            [switch]$DeepScan
        )
        $result = @{
            MediaScanned = 0
            Outdated     = @()   # list of @{ Drive; File; SignedBy; Status }
            Error        = $null
        }
        $volumes = @()
        try {
            $volumes = @(Get-Volume -ErrorAction Stop | Where-Object {
                $_.DriveType -in 'Removable','CD-ROM' -and -not [string]::IsNullOrWhiteSpace($_.DriveLetter)
            })
        }
        catch {
            $result.Error = "Volume enumeration failed: $($_.Exception.Message)"
            return $result
        }
        if ($volumes.Count -eq 0) { return $result }
        
        $efiFiles = 'bootx64.efi','bootia32.efi','bootx86.efi','bootaa64.efi','bootaa32.efi','bootarm.efi'
        foreach ($vol in $volumes) {
            $drv = "$($vol.DriveLetter):"
            $result.MediaScanned++
            foreach ($name in $efiFiles) {
                $path = Join-Path $drv "EFI\boot\$name"
                if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) { continue }
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
                    $issuer = if ($null -ne $sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { '' }
                    $is2011 = $issuer -match '(?i)(Microsoft Windows Production PCA 2011|Microsoft Corporation UEFI CA 2011)'
                    $is2023 = $issuer -match '(?i)(Windows UEFI CA 2023|Microsoft UEFI CA 2023|Microsoft Option ROM UEFI CA 2023)'
                    if ($is2011 -and -not $is2023) {
                        $result.Outdated += @{
                            Drive    = $drv
                            File     = "EFI\boot\$name"
                            SignedBy = 'PCA 2011'
                            Status   = 'Outdated'
                        }
                    }
                }
                catch {
                    Write-Log "WARNING" "Signature check failed for $($path): $($_.Exception.Message)"
                }
            }
            
            if ($DeepScan) {
                $wimCandidates = 'sources\boot.wim','sources\install.wim','sources\install.esd'
                foreach ($wim in $wimCandidates) {
                    $wimPath = Join-Path $drv $wim
                    if (-not (Test-Path -LiteralPath $wimPath -ErrorAction SilentlyContinue)) { continue }
                    try {
                        # Lightweight presence report (full DISM extraction is out of scope here)
                        $info = Get-WindowsImage -ImagePath $wimPath -Index 1 -ErrorAction Stop
                        $result.Outdated += @{
                            Drive    = $drv
                            File     = $wim
                            SignedBy = "Image: $($info.ImageName)"
                            Status   = 'Review (WIM - manual verification recommended)'
                        }
                    }
                    catch {
                        Write-Log "INFO" "Could not inspect $($wimPath): $($_.Exception.Message)"
                    }
                }
            }
        }
        return $result
    }
    
    # Look up whether Microsoft publishes a vendor-signed KEK CA 2023 update for the current PK.
    # Downloads kek_update_map.json from microsoft/secureboot_objects and checks whether the
    # current PK thumbprint has an available update record. Intended to guide Action Required
    # decisions (wait on OEM firmware vs. WU opt-in) when Event 1795 or 1803 is firing.
    # Reference: garlin's Check_UEFI-CA2023.ps1 Check-KEKUpdateMap (https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates)
    function Get-KekUpdateAvailability {
        param (
            [string]$PkThumbprint,
            [int]$TimeoutSec = 10
        )
        $result = @{
            Succeeded       = $false
            Available       = $false
            Vendors         = @()
            MicrosoftSigned = $false
            Error           = $null
        }
        if ([string]::IsNullOrWhiteSpace($PkThumbprint)) {
            $result.Error = 'PK thumbprint unavailable'
            return $result
        }
        $url = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/KEK/kek_update_map.json'
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
            $json = $response.Content | ConvertFrom-Json
        }
        catch {
            $result.Error = "Fetch/parse failed: $($_.Exception.Message)"
            return $result
        }
        
        $tp = $PkThumbprint.ToUpperInvariant()
        # The JSON is typically an object keyed by PK thumbprint, each value describing available
        # vendor updates. Support both that and the array-of-records shape defensively.
        $record = $null
        if ($json -is [System.Collections.IEnumerable] -and -not ($json -is [string])) {
            foreach ($entry in $json) {
                $entryTp = $null
                foreach ($p in 'thumbprint','PKThumbprint','pk_thumbprint','pkSha1') {
                    if ($entry.PSObject.Properties[$p]) { $entryTp = [string]$entry.$p; break }
                }
                if ($null -ne $entryTp -and $entryTp.ToUpperInvariant() -eq $tp) { $record = $entry; break }
            }
        }
        elseif ($json.PSObject.Properties[$tp]) {
            $record = $json.$tp
        }
        elseif ($json.PSObject.Properties[$PkThumbprint]) {
            $record = $json.$PkThumbprint
        }
        
        $result.Succeeded = $true
        if ($null -eq $record) { return $result }
        
        $result.Available = $true
        $vendorList = @()
        foreach ($p in 'vendors','Vendors','vendor_updates','updates') {
            if ($record.PSObject.Properties[$p]) {
                $vals = $record.$p
                if ($vals -is [System.Collections.IEnumerable] -and -not ($vals -is [string])) {
                    foreach ($v in $vals) {
                        if ($v -is [string]) { $vendorList += $v }
                        elseif ($v.PSObject.Properties['vendor']) { $vendorList += [string]$v.vendor }
                        elseif ($v.PSObject.Properties['name'])   { $vendorList += [string]$v.name }
                    }
                }
                break
            }
        }
        $result.Vendors = $vendorList | Select-Object -Unique
        foreach ($p in 'microsoftSigned','MicrosoftSigned','msSigned','ms_signed') {
            if ($record.PSObject.Properties[$p] -and $record.$p) { $result.MicrosoftSigned = $true; break }
        }
        return $result
    }
    
    # Read expected SVN from Windows Update staging file (DBXUpdateSVN.bin).
    # Source: https://github.com/microsoft/secureboot_objects
    #
    # The .bin file ships with an ASN.1 SEQUENCE authenticode wrapper (bytes 40..41 ==
    # 0x30 0x82) that the firmware UEFI variable does NOT carry. Strip it before
    # handing bytes to Get-DbxSignatureData; otherwise the EFI_SIGNATURE_LIST parser
    # walks the wrapper as if it were a sig list and silently returns nothing - the
    # symptom is a "Staged SVN: N/A" card row on devices that clearly have a staged
    # update file. Use the same Get-StrippedDbxBinBytes helper Compare-DbxAgainstStagedBins
    # already relies on so both code paths see identical content.
    #
    # Picks the max-by-version across all BootMgr-prefixed entries to match the
    # canonical proper selection (in case a future staged file ships
    # multiple SVN candidates for the same component).
    function Get-WindowsUpdateSVN {
        $svnFile = "$env:SystemRoot\System32\SecureBootUpdates\DBXUpdateSVN.bin"
        if (-not (Test-Path $svnFile)) {
            return $null
        }
        try {
            $fileBytes = [System.IO.File]::ReadAllBytes($svnFile)
            $clean     = Get-StrippedDbxBinBytes -Bytes $fileBytes
            $sigData   = Get-DbxSignatureData -Bytes $clean
            $matches   = @($sigData | Where-Object { $_ -match "^$($script:EFI_BOOTMGR_DBXSVN_GUID)" })
            if ($matches.Count -eq 0) {
                return $null
            }
            $maxVer = $null
            $maxStr = $null
            foreach ($m in $matches) {
                $svn = Get-SignatureDataSVN $m
                if ([string]::IsNullOrWhiteSpace($svn)) { continue }
                try { $v = [version]$svn } catch { continue }
                if ($null -eq $maxVer -or $v -gt $maxVer) { $maxVer = $v; $maxStr = $svn }
            }
            return $maxStr
        }
        catch {
            Write-Log "WARNING" "Failed to read DBXUpdateSVN.bin: $($_.Exception.Message)"
            return $null
        }
    }
    
    # Get Secure Boot SVN status. Single canonical contract: always returns the same
    # field shape regardless of whether the Get-SecureBootSVN cmdlet is available
    # (KB5077241+, Stage 2 onwards). Now that Get-DbxComponentSVNs replicates the
    # cmdlet's BootMgr / CdBoot / WdsMgr extraction without the PowerShell#27058
    # bug, the per-DBX values (FirmwareSVN, StagedSVN, DbxSVN, WindowsUpdateSVN)
    # come from raw bytes on every device - cmdlet or not. The cmdlet is still
    # consulted only for fields that have no raw equivalent (BootManagerSVN and
    # BootManagerPath, which read the on-disk boot manager binary), and as a
    # cross-check signal so PowerShell#27058 disagreements are logged.
    #
    # Source: https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates
    function Get-SecureBootSVNStatus {
        param ([byte[]]$DbxBytes)
        # Step 1 - Resolve all three boot-component SVNs from raw DBX bytes (canonical
        # logic via Get-DbxComponentSVNs). One parser invocation feeds both the
        # FirmwareSVN value used downstream and the parity log line below.
        $componentSvnMap = if ($null -ne $DbxBytes -and $DbxBytes.Length -gt 0) {
            Get-DbxComponentSVNs -DbxBytes $DbxBytes
        }
        else { [ordered]@{ BootMgr = $null; CdBoot = $null; WdsMgr = $null } }
        $currentSVN = $componentSvnMap.BootMgr
        $svnPresent = ($null -ne $currentSVN)
        # Always log per-component SVN regardless of cmdlet availability or DBX state.
        $bmLog = if ($null -ne $componentSvnMap.BootMgr) { $componentSvnMap.BootMgr } else { 'absent' }
        $cdLog = if ($null -ne $componentSvnMap.CdBoot)  { $componentSvnMap.CdBoot }  else { 'absent' }
        $wdLog = if ($null -ne $componentSvnMap.WdsMgr)  { $componentSvnMap.WdsMgr }  else { 'absent' }
        Write-Log "INFO" "Raw DBX SVN per component (max-by-version): BootMgr=$bmLog | CdBoot=$cdLog | WdsMgr=$wdLog"
        
        # Step 2 - Resolve Windows Update staged SVN from DBXUpdateSVN.bin (raw-byte
        # parser, identical on all stages). The "pending" signal is gated on the
        # documented compliance floor: if firmware SVN is already at or above the
        # active enforcement target, a higher-numbered staged SVN is "future work"
        # (Microsoft can ship a newer .bin ahead of any actual enforcement bump),
        # not a pending update the operator needs to act on. Treating staged > firmware
        # as pending here would cascade into a "Pending SVN Reboot" overlay and an
        # "SVN update pending" callout on devices that are already compliant per floor.
        $windowsUpdateSVN = Get-WindowsUpdateSVN
        $floorBootMgr     = $script:SVN_COMPLIANCE_FLOORS.BootMgr
        $floorMet         = $false
        if (-not [string]::IsNullOrWhiteSpace($currentSVN) -and -not [string]::IsNullOrWhiteSpace($floorBootMgr)) {
            try { $floorMet = ([version]$currentSVN) -ge ([version]$floorBootMgr) } catch { }
        }
        $svnUpdatePending = $false
        if (-not $floorMet -and $null -ne $windowsUpdateSVN) {
            $svnUpdatePending = ($null -eq $currentSVN) -or ([version]$currentSVN -lt [version]$windowsUpdateSVN)
        }
        
        # Step 3 - Try the cmdlet for the two fields we cannot derive from raw bytes
        # (BootManagerSVN, BootManagerPath) plus the authoritative ComplianceStatus
        # string. FirmwareSVN/StagedSVN are NEVER read from the cmdlet output - we
        # already have them, bug-free, from raw bytes.
        $cmdletResult = $null
        if ($script:HasSVNCmdlet) {
            try { $cmdletResult = Get-SecureBootSVN -ErrorAction Stop }
            catch { Write-Log "WARNING" "Get-SecureBootSVN failed: $($_.Exception.Message)" }
        }
        
        # Step 4 - Cross-check: when the cmdlet IS available, log whenever its FirmwareSVN
        # disagrees with our raw-DBX max. That is the PowerShell#27058 signature: the
        # cmdlet returns whichever BootMgr-GUID entry appears LAST in DBX order rather
        # than the max. Diagnostic-only; the result hash always uses the raw value so
        # the bug never affects downstream logic.
        if ($null -ne $cmdletResult -and -not [string]::IsNullOrWhiteSpace($currentSVN) -and
            -not [string]::IsNullOrWhiteSpace([string]$cmdletResult.FirmwareSVN)) {
            try {
                $rawVer = [version]$currentSVN
                $cmdVer = [version]$cmdletResult.FirmwareSVN
                if ($rawVer -ne $cmdVer) {
                    Write-Log "WARNING" ("Get-SecureBootSVN FirmwareSVN mismatch: cmdlet=$($cmdletResult.FirmwareSVN), raw-DBX max=$currentSVN. " +
                        "Likely PowerShell/PowerShell#27058 bug. Cmdlet reports last-in-DBX-order instead of max. Using raw-DBX value.")
                }
            }
            catch {
                # Swallow
            }
        }
        
        # Step 5 - Resolve compliance and the cmdlet-only fields. Same hash shape
        # returns on every device.
        #
        # Compliance is authoritative from the documented floor ($script:SVN_COMPLIANCE_FLOORS):
        # firmware BootMgr SVN >= floor -> Compliant. The cmdlet's own ComplianceStatus
        # ("Not compliant - Firmware does not match boot manager", etc.) is computed
        # from the cmdlet's FirmwareSVN reading, which #27058 silently under-reports
        # (e.g. cmdlet=2.0 vs raw-DBX max=7.0 on a Stage-4-complete device). Trusting
        # that string flips the card to "Not compliant" on a perfectly compliant
        # device. Use the floor as the authoritative signal regardless of cmdlet path,
        # and only fall back to the cmdlet's narrative when the floor check fails -
        # at that point the cmdlet's failure-mode wording is still useful color.
        # ($floorMet was computed in Step 2 alongside $svnUpdatePending.)
        if ($null -ne $cmdletResult) {
            $bootManagerSvn  = if ($cmdletResult.BootManagerSVN) { $cmdletResult.BootManagerSVN } else { 'N/A' }
            $bootManagerPath = $cmdletResult.BootManagerPath
            $source          = 'Raw DBX (FirmwareSVN/StagedSVN) + Get-SecureBootSVN (BootManagerSVN/Compliance)'
            if ($floorMet) {
                $isCompliant      = $true
                $complianceStatus = "Compliant (Firmware SVN $currentSVN >= floor $floorBootMgr)"
            }
            else {
                $isCompliant      = $cmdletResult.ComplianceStatus -match '^Compliant'
                $complianceStatus = $cmdletResult.ComplianceStatus
            }
        }
        else {
            $bootManagerSvn  = 'N/A'
            $bootManagerPath = $null
            $source          = 'Raw DBX'
            if ($floorMet) {
                $isCompliant      = $true
                $complianceStatus = "Compliant (Firmware SVN $currentSVN >= floor $floorBootMgr)"
            }
            else {
                $isCompliant = $svnPresent -and ($null -ne $windowsUpdateSVN) -and ([version]$currentSVN -ge [version]$windowsUpdateSVN)
                # Treat as compliant if SVN is in DBX and there's no staging file to compare against
                if ($svnPresent -and $null -eq $windowsUpdateSVN) { $isCompliant = $true }
                $complianceStatus = if ($isCompliant) {
                    'Compliant'
                }
                elseif (-not $svnPresent -and $null -eq $windowsUpdateSVN) {
                    'SVN not yet in DBX (pending SVN reboot or not yet applied)'
                }
                elseif (-not $svnPresent) {
                    'SVN not present in DBX'
                }
                else {
                    "DBX SVN $currentSVN < staged $windowsUpdateSVN"
                }
            }
        }
        
        # Always-raw component fields (CdBoot / WdsMgr). The cmdlet conventionally
        # only surfaces FirmwareSVN / BootManagerSVN / StagedSVN; the two non-bootmgr
        # SVN-keyed components live alongside in DBX and are useful as a parity
        # readout (especially when the BootMgr value is the only one moving). Sourced
        # from the same Get-DbxComponentSVNs pass that fed FirmwareSVN above so the
        # values are guaranteed consistent with the per-component log line.
        $cdBootSvn = if ($null -ne $componentSvnMap.CdBoot) { $componentSvnMap.CdBoot } else { 'N/A' }
        $wdsMgrSvn = if ($null -ne $componentSvnMap.WdsMgr) { $componentSvnMap.WdsMgr } else { 'N/A' }
        return @{
            FirmwareSVN      = if ($svnPresent) { $currentSVN } else { 'N/A' }
            BootManagerSVN   = $bootManagerSvn
            StagedSVN        = if ($null -ne $windowsUpdateSVN) { $windowsUpdateSVN } else { 'N/A' }
            CdBootSVN        = $cdBootSvn
            WdsMgrSVN        = $wdsMgrSvn
            ComplianceStatus = $complianceStatus
            BootManagerPath  = $bootManagerPath
            IsCompliant      = $isCompliant
            Source           = $source
            DbxSVN           = $currentSVN
            WindowsUpdateSVN = $windowsUpdateSVN
            SvnUpdatePending = $svnUpdatePending
        }
    }
    
    # Helper function: Parse UEFI database and return both certs and raw bytes.
    # Raw bytes are ALWAYS fetched (one NVRAM read per variable) because downstream
    # features need them regardless of whether -Decoded is available:
    #   - Raw DBX SVN extraction (Get-DbxBootMgrSVN)
    #   - Staged-file DBX validation (Compare-DbxAgainstStagedBins)
    #   - Binary-vs-text heuristic on dbx
    #   - Signature-data byte parsing (Get-DbxSignatureData)
    # -Decoded (KB5077241+, Feb 2025) is used purely as a cert-parse enrichment:
    # on success, certs are sourced from the cmdlet's structured output; on failure
    # or absence, certs fall back to Parse-UefiSignatureDatabase over the same raw
    # bytes. Historical bug: the pre-fix version returned Bytes=$null on -Decoded
    # success, silently breaking every byte-dependent feature on KB5077241+ devices.
    function Get-UefiDatabaseCerts {
        param (
            [string]$Name   # db, KEK, dbx, dbDefault, PK, PKDefault, KEKDefault, dbxDefault
        )
        # Step 1: always fetch raw bytes first. If this fails, the variable is
        # unavailable on this device. Nothing else will work either, bail early.
        $rawBytes      = $null
        $rawAttributes = $null
        try {
            $uefiVar       = Get-SecureBootUEFI -Name $Name -ErrorAction Stop
            $rawBytes      = $uefiVar.Bytes
            $rawAttributes = $uefiVar.Attributes
        }
        catch {
            Write-Log "WARNING" "Failed to read UEFI variable '$Name': $($_.Exception.Message)"
            return @{ Certs = @(); Bytes = $null; Attributes = $null; UsedDecoded = $false }
        }
        
        # Step 2: prefer -Decoded for cert parsing when available.
        if ($script:HasDecodedParam) {
            try {
                $decoded = Get-SecureBootUEFI -Name $Name -Decoded -ErrorAction Stop
                # -Decoded returns flat objects with Subject/ValidFrom/ValidTo rather than
                # X509Certificate2 instances. Normalize to the NotBefore/NotAfter shape the
                # downstream code expects, and filter out SHA256 hash-only entries (no Subject).
                $entries = @($decoded)
                $certs = @()
                foreach ($entry in $entries) {
                    if (-not [string]::IsNullOrWhiteSpace($entry.Subject)) {
                        $certObj = [PSCustomObject]@{
                            Subject   = $entry.Subject
                            NotBefore = if ($entry.ValidFrom) { [DateTime]$entry.ValidFrom } else { [DateTime]::MinValue }
                            NotAfter  = if ($entry.ValidTo)   { [DateTime]$entry.ValidTo }   else { [DateTime]::MaxValue }
                        }
                        $certs += $certObj
                    }
                }
                if ($certs.Count -gt 0) {
                    $skipped = $entries.Count - $certs.Count
                    if ($skipped -gt 0) { Write-Log "INFO" "$Name -Decoded: $($certs.Count) certs, $skipped hash entries skipped" }
                    return @{ Certs = $certs; Bytes = $rawBytes; Attributes = $rawAttributes; UsedDecoded = $true }
                }
                Write-Log "INFO" "-Decoded returned no certificate entries for $Name ($($entries.Count) hash-only entries), falling back to raw parse"
            }
            catch {
                Write-Log "WARNING" "-Decoded failed for $Name ($($_.Exception.Message)), falling back to raw parse"
            }
        }
        
        # Step 3: raw-byte cert parse. Either -Decoded is unavailable, it failed,
        # or it returned hash-only entries. Parse-UefiSignatureDatabase handles both
        # cases (returns @() when no certs are present).
        $certs = Parse-UefiSignatureDatabase -Bytes $rawBytes
        return @{ Certs = $certs; Bytes = $rawBytes; Attributes = $rawAttributes; UsedDecoded = $false }
    }
    
    # Test an attribute returned by the inbox Get-SecureBootUEFI cmdlet. The
    # Attributes property is normally a flags enum, but the text fallback keeps
    # the check compatible with hosts that expose its display-name representation.
    function Test-UefiVariableAttribute {
        param (
            [AllowNull()]
            $Attributes,
            [Parameter(Mandatory = $true)]
            [uint32]$Mask,
            [Parameter(Mandatory = $true)]
            [string]$DisplayName
        )
        
        if ($null -eq $Attributes) { return $false }
        
        try {
            if ($Attributes -is [System.Enum] -or
                $Attributes -is [byte] -or
                $Attributes -is [uint16] -or
                $Attributes -is [uint32] -or
                $Attributes -is [uint64] -or
                $Attributes -is [int16] -or
                $Attributes -is [int32] -or
                $Attributes -is [int64]) {
                return (([uint32]$Attributes -band $Mask) -ne 0)
            }
        }
        catch {
            # Fall through to the display-name representation.
        }
        
        $attributeText = (@($Attributes) | ForEach-Object { [string]$_ }) -join ' '
        $normalizedText = ($attributeText.ToUpperInvariant() -replace '[^A-Z0-9]+', ' ').Trim()
        $normalizedName = ($DisplayName.ToUpperInvariant() -replace '[^A-Z0-9]+', ' ').Trim()
        return $normalizedText -match ('(^| )' + [regex]::Escape($normalizedName) + '( |$)')
    }
    
    # Consolidated accessor that wraps Get-UefiDatabaseCerts with common post-processing:
    #   - Extracts Common Name (CN) from each Subject
    #   - Flags hypervisor-managed platforms (VMware owner GUID / VirtualBox subject)
    #   - Flags untrusted placeholder PKs
    #   - Optional -MicrosoftOnly filter
    # Returns @{ Subjects; CommonNames; Hypervisor; Trusted; Raw }. Caller picks what it needs.
    # Reference: garlin's Check_UEFI-CA2023.ps1 Get-UEFICert (https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates).
    function Get-UefiCertSubjects {
        param(
            [ValidateSet('PK','KEK','db','dbx','PKDefault','KEKDefault','dbDefault','dbxDefault')]
            [string]$Name,
            [switch]$MicrosoftOnly
        )
        $raw = Get-UefiDatabaseCerts -Name $Name
        $subjects   = @()
        $commonName = @()
        $hypervisor = $null
        $trusted    = $true
        foreach ($cert in $raw.Certs) {
            if ([string]::IsNullOrWhiteSpace($cert.Subject)) { continue }
            if ($cert.PSObject.Properties['Hypervisor'] -and $null -ne $cert.Hypervisor) {
                $hypervisor = $cert.Hypervisor
            }
            elseif ($cert.Subject -match '(?i)VirtualBox') {
                $hypervisor = 'VirtualBox'
            }
            if ($cert.Subject -match '(?i)(DO NOT|Example)') { $trusted = $false }
            if ($MicrosoftOnly -and $cert.Subject -notmatch '(?i)(Microsoft|Mosby)') { continue }
            $subjects += $cert.Subject
            $cn = [regex]::Match($cert.Subject, '(?i)CN=([^,]+)')
            if ($cn.Success) { $commonName += $cn.Groups[1].Value.Trim() }
        }
        return @{
            Subjects    = $subjects
            CommonNames = $commonName
            Hypervisor  = $hypervisor
            Trusted     = $trusted
            Raw         = $raw
        }
    }
    
    # Helper function: Check if Secure Boot is enabled on this machine
    # Returns: 'Enabled', 'Disabled', or 'NotApplicable' (non-UEFI / exception thrown)
    # Uses direct UEFI variable access to bypass Windows validation failures (e.g., 1801 logic)
    function Get-SecureBootStatus {
        try {
            # Step 1: Check SetupMode
            $setupModeBytes = (Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop).Bytes
            if ($setupModeBytes.Count -eq 0) { throw "SetupMode is empty" }
            $setupMode = $setupModeBytes[0]
            Write-Log "INFO" "SetupMode: $setupMode"
            
            if ($setupMode -eq 1) {
                # Setup Mode (no PK installed) - Secure Boot is disabled, but variables are accessible
                return 'Disabled'
            }
            elseif ($setupMode -eq 0) {
                # User Mode (PK installed) - Check SecureBoot state
                $secureBootBytes = (Get-SecureBootUEFI -Name SecureBoot -ErrorAction Stop).Bytes
                if ($secureBootBytes.Count -eq 0) { throw "SecureBoot is empty" }
                $secureBoot = $secureBootBytes[0]
                
                if ($secureBoot -eq 1) {
                    # Enabled - Validate all core variables exist and are non-empty
                    "PK","KEK","db","dbx" | ForEach-Object {
                        $var = Get-SecureBootUEFI -Name $_ -ErrorAction Stop
                        if ($var.Bytes.Count -eq 0) {
                            throw "UEFI variable '$_' is empty"
                        }
                    }
                    return 'Enabled'
                }
                else {
                    # SecureBoot is 0 - Disabled
                    return 'Disabled'
                }
            }
            else {
                throw "Unexpected SetupMode value: $setupMode"
            }
        }
        catch {
            Write-Log "INFO" "Get-SecureBootUEFI exception: $($_.Exception.Message)"
            if ($_.Exception.Message -match "Cmdlet not supported") {
                # Runtime services not exposed (likely non-UEFI)
                return 'NotApplicable'
            }
            elseif ($_.Exception.Message -match "Unable to set proper privileges") {
                # Token privilege issue
                return 'NotApplicable'
            }
            else {
                # Other exceptions (e.g., broken variable interface)
                return 'NotApplicable'
            }
        }
    }
    
    ###########
    # Sources #
    ###########
    # Get-SecureBootUEFI returns Name, Bytes, and Attributes through Windows'
    # inbox Microsoft.SecureBoot.Commands module. The existing db read therefore
    # provides the stored UEFI attribute flags without script-supplied native
    # interop or direct token-privilege manipulation.
    # https://learn.microsoft.com/en-us/powershell/module/secureboot/get-securebootuefi
    # https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11#appendix-b--secure-boot-apis
    
    # -----------------------------------------------
    # Secure Boot Event ID Reference (Microsoft-Windows-TPM-WMI)
    # Source: https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69
    # -----------------------------------------------
    # State / progress events:
    #   1801 = Certs available but not applied (action required)
    #   1800 = Reboot required to continue
    #   1799 = Boot manager (signed with 2023 cert) installed
    #   1808 = Fully updated - all certs + boot manager applied (compliant)
    #
    # Certificate deployment events (success):
    #   1043 = KEK updated with KEK CA 2023
    #   1044 = Option ROM CA 2023 added to DB
    #   1045 = Microsoft UEFI CA 2023 added to DB
    #   1036 = DB variable applied
    #   1034 = DBX variable applied
    #   1037 = 2011 CA revoked in DBX (Mitigation 3)
    #   1042 = Boot Manager SVN applied to DBX (Mitigation 4)
    #
    # Blocker / warning events:
    #   1032 = BitLocker conflict (would enter recovery)
    #   1033 = Vulnerable bootloader in EFI partition
    #
    # Firmware / prerequisite error events:
    #   1795 = Firmware returned an error (rejected the write)
    #   1796 = Unexpected error during variable update (Windows retries on reboot)
    #   1797 = Windows UEFI CA 2023 not in DB (prerequisite failure)
    #   1798 = Boot manager not signed with 2023 cert (DBX update blocked)
    #   1802 = Update blocked - known firmware/hardware limitation
    #   1803 = PK-signed KEK not found for this device (OEM hasn't provided signed KEK)
    # -----------------------------------------------
    
    # Descriptions for each event ID
    $script:SecureBootEventDescriptions = @{
        # State events
        1801 = 'Certs available but not applied'
        1800 = 'Reboot required to continue'
        1799 = 'Boot manager installed'
        1808 = 'Fully updated (all certs + boot manager)'
        # Deployment success events
        1043 = 'KEK updated with KEK CA 2023'
        1044 = 'Option ROM CA 2023 added to DB'
        1045 = 'Microsoft UEFI CA 2023 added to DB'
        1036 = 'DB variable applied'
        1034 = 'DBX variable applied'
        1037 = '2011 CA revoked in DBX (Mitigation 3)'
        1042 = 'Boot Manager SVN applied to DBX (Mitigation 4)'
        # Blocker events
        1032 = 'BitLocker conflict'
        1033 = 'Vulnerable bootloader in EFI partition'
        # Firmware / prerequisite errors
        1795 = 'Firmware returned an error'
        1796 = 'Unexpected update error (will retry on reboot)'
        1797 = 'Windows UEFI CA 2023 not in DB (DBX prerequisite failure)'
        1798 = 'Boot manager not signed with 2023 cert'
        1802 = 'Update blocked (known firmware limitation)'
        1803 = 'PK-signed KEK not found (OEM issue)'
    }
    
    # All event IDs being query'd for (18 total per MS KB5016061)
    $script:SecureBootEventIds = @(
        1032, 1033, 1034, 1036, 1037, 1042, 1043, 1044, 1045,
        1795, 1796, 1797, 1798, 1799, 1800, 1801, 1802, 1803, 1808
    )
    
    # Helper function: Query ALL Secure Boot events from the System event log
    # Returns a hashtable with:
    #   Status       - Compliant / ActionRequired / Pending (based on most recent state event)
    #   EventId      - Most recent state event ID
    #   EventTime    - Timestamp of most recent state event
    #   EventMessage - Event description
    #   AllEvents    - Full list of parsed events (for summary)
    #   EventSummary - Aggregated list: @{ Id; Description; Count; FirstSeen; LastSeen }
    function Get-CertUpdateEventStatus {
        $rawEvents = $null
        
        # Primary method: Get-WinEvent
        try {
            $rawEvents = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = 'Microsoft-Windows-TPM-WMI'
                Id           = $script:SecureBootEventIds
            } -ErrorAction Stop
            Write-Log "INFO" "Get-WinEvent succeeded: $(@($rawEvents).Count) event(s) found"
        }
        catch {
            if ($_.Exception.Message -match 'No events were found') {
                Write-Log "INFO" "Get-WinEvent: No matching Secure Boot events found"
                $rawEvents = @()
            }
            else {
                Write-Log "WARNING" "Get-WinEvent failed: $($_.Exception.Message). Attempting Get-EventLog fallback."
                try {
                    $rawEvents = Get-EventLog -LogName System -Source 'Microsoft-Windows-TPM-WMI' `
                        -InstanceId $script:SecureBootEventIds -ErrorAction Stop
                    Write-Log "INFO" "Get-EventLog fallback succeeded: $(@($rawEvents).Count) event(s) found"
                }
                catch {
                    Write-Log "WARNING" "Get-EventLog fallback also failed: $($_.Exception.Message)"
                    $rawEvents = @()
                }
            }
        }
        
        $rawEvents = @($rawEvents)
        
        # Normalize events to a common format, extracting BucketId/Confidence/SkipReason from message text
        $parsedEvents = foreach ($ev in $rawEvents) {
            $id   = if ($null -ne $ev.Id) { $ev.Id } else { $ev.InstanceId }
            $time = if ($null -ne $ev.TimeCreated) { $ev.TimeCreated } else { $ev.TimeGenerated }
            $msg  = if ($null -ne $ev.Message) { $ev.Message } else { '' }
            
            # Extract BucketId, BucketConfidenceLevel, SkipReason from event message (1801/1808 carry these)
            $bucketId    = $null
            $confidence  = $null
            $skipReason  = $null
            if ($msg -match 'BucketId:\s*(.+?)(\r|\n|$)')             { $bucketId   = $matches[1].Trim() }
            if ($msg -match 'BucketConfidenceLevel:\s*(.+?)(\r|\n|$)') { $confidence = $matches[1].Trim() }
            if ($msg -match 'SkipReason:\s*(KI_\d+)')                 { $skipReason = $matches[1] }
            
            [PSCustomObject]@{
                Id          = [int]$id
                Time        = [datetime]$time
                Description = if ($script:SecureBootEventDescriptions.ContainsKey([int]$id)) { $script:SecureBootEventDescriptions[[int]$id] } else { "Unknown event $id" }
                BucketId    = $bucketId
                Confidence  = $confidence
                SkipReason  = $skipReason
            }
        }
        
        # Sort chronologically (oldest first for display, newest first for state)
        $parsedEvents = @($parsedEvents | Sort-Object -Property Time)
        
        # Build aggregated summary: group by ID, count occurrences, track first/last seen
        $eventSummary = @()
        if ($parsedEvents.Count -gt 0) {
            $grouped = $parsedEvents | Group-Object -Property Id
            foreach ($group in ($grouped | Sort-Object { ($_.Group | Select-Object -First 1).Time })) {
                $sorted = $group.Group | Sort-Object Time
                $eventSummary += [PSCustomObject]@{
                    Id          = [int]$group.Name
                    Description = $sorted[0].Description
                    Count       = $group.Count
                    FirstSeen   = $sorted[0].Time
                    LastSeen    = $sorted[-1].Time
                }
            }
        }
        
        # Log the summary
        if ($eventSummary.Count -gt 0) {
            Write-Log "INFO" "Event log summary:"
            foreach ($entry in ($eventSummary | Sort-Object LastSeen)) {
                $timeStr = $entry.LastSeen.ToString('yyyy-MM-dd HH:mm')
                Write-Log "INFO" ("  {0}  [{1}] {2} ({3}x)" -f $timeStr, $entry.Id, $entry.Description, $entry.Count)
            }
        }
        
        # Determine state from the most recent STATE event
        # These are the events that indicate overall deployment status:
        #   1801 = certs available but not applied (action required)
        #   1803 = PK-signed KEK not found - OEM blocker (action required)
        #   1800 = reboot required to continue
        #   1799 = 2023 boot manager installed
        #   1037 = PCA 2011 revoked in DBX (Stage 3 complete)
        #   1042 = SVN applied to DBX (Stage 4 complete)
        #   1808 = fully compliant
        $stateEventIds = @(1037, 1042, 1799, 1800, 1801, 1803, 1808)
        $stateEvents = @($parsedEvents | Where-Object { $stateEventIds -contains $_.Id } | Sort-Object Time -Descending)
        
        if ($stateEvents.Count -eq 0 -and $parsedEvents.Count -eq 0) {
            return @{
                Status       = 'Pending'
                EventId      = $null
                EventTime    = $null
                EventMessage      = 'No Secure Boot certificate events found in System log'
                AllEvents         = @()
                EventSummary      = @()
                BucketId          = $null
                Confidence        = $null
                SkipReason        = $null
                RebootCorrelation = $null
            }
        }
        
        # If ther are deployment events (1043-1045, 1036, etc.) but no state events,
        # certs are being applied but no state conclusion yet
        if ($stateEvents.Count -eq 0) {
            $latest = $parsedEvents | Select-Object -Last 1
            return @{
                Status       = 'Pending'
                EventId      = $latest.Id
                EventTime    = $latest.Time
                EventMessage      = 'Deployment events found but no state events (1801/1808) yet'
                AllEvents         = $parsedEvents
                EventSummary      = $eventSummary
                BucketId          = $null
                Confidence        = $null
                SkipReason        = $null
                RebootCorrelation = $null
            }
        }
        
        $latestState = $stateEvents[0]
        
        switch ($latestState.Id) {
            1808 {
                $status = 'Compliant'
                $msg    = 'Fully updated - all certs + boot manager applied (Event 1808)'
            }
            1042 {
                $status = 'Pending'
                $msg    = 'SVN applied to DBX - reboot required to finalize (Event 1042)'
            }
            1037 {
                $status = 'Pending'
                $msg    = 'PCA 2011 revoked in DBX - reboot required to finalize (Event 1037)'
            }
            1800 {
                $status = 'Pending'
                $msg    = 'Reboot required to continue (Event 1800)'
            }
            1801 {
                $status = 'ActionRequired'
                $msg    = 'Certs available but not applied (Event 1801)'
            }
            1803 {
                $status = 'ActionRequired'
                $msg    = 'PK-signed KEK 2023 not available via WU - awaiting OEM publication (Event 1803)'
            }
            1799 {
                $status = 'Pending'
                $msg    = 'Boot manager signed with Windows UEFI CA 2023 installed successfully (Event 1799)'
            }
            default {
                $status = 'Pending'
                $msg    = "Event $($latestState.Id) - treating as Pending"
            }
        }
        
        Write-Log "INFO" "Most recent state event: ID $($latestState.Id) at $($latestState.Time)"
        
        # Extract BucketId/Confidence from 1801 or 1808 events only (1800/1799 don't carry meaningful bucket metadata)
        $bucketEvent = $stateEvents | Where-Object { $null -ne $_.BucketId -and $_.Id -in @(1801, 1808) } | Select-Object -First 1
        if ($null -ne $bucketEvent) {
            # Clean up Confidence: strip "UpdateType:" prefix if present (e.g., "UpdateType:ActionRequired" -> "ActionRequired")
            if ($bucketEvent.Confidence -match '^UpdateType:(.*)$') {
                $bucketEvent.Confidence = $matches[1].Trim()
            }
            # If confidence is empty/whitespace after cleanup, null it out
            if ([string]::IsNullOrWhiteSpace($bucketEvent.Confidence)) {
                $bucketEvent.Confidence = $null
            }
            Write-Log "INFO" "Bucket: $($bucketEvent.BucketId)"
            if ($null -ne $bucketEvent.Confidence) {
                Write-Log "INFO" "Confidence: $($bucketEvent.Confidence)"
            }
            if ($null -ne $bucketEvent.SkipReason) {
                Write-Log "WARNING" "SkipReason: $($bucketEvent.SkipReason) (Known firmware issue)"
            }
        }
        
        # Detect 1800 -> 1799 progression (reboot between them confirms the sequence)
        $rebootCorrelation = $null
        $ev1800 = $parsedEvents | Where-Object { $_.Id -eq 1800 } | Sort-Object Time -Descending | Select-Object -First 1
        $ev1799 = $parsedEvents | Where-Object { $_.Id -eq 1799 } | Sort-Object Time -Descending | Select-Object -First 1
        if ($null -ne $ev1800 -and $null -ne $ev1799 -and $ev1799.Time -gt $ev1800.Time) {
            $rebootCheck = Get-RebootsBetweenTimes -After $ev1800.Time -Before $ev1799.Time
            if ($rebootCheck.Found) {
                $bootTimeStr = $rebootCheck.BootTimes[-1].ToString('yyyy-MM-dd HH:mm')
                Write-Log "INFO" "Reboot detected between 1800 ($($ev1800.Time.ToString('HH:mm'))) and 1799 ($($ev1799.Time.ToString('HH:mm'))): boot at $bootTimeStr"
                $rebootCorrelation = @{
                    Event1800Time = $ev1800.Time
                    Event1799Time = $ev1799.Time
                    BootTimes     = $rebootCheck.BootTimes
                    BootCount     = $rebootCheck.Count
                    Confirmed     = $true
                }
            }
            else {
                Write-Log "INFO" "1800 ($($ev1800.Time.ToString('HH:mm'))) -> 1799 ($($ev1799.Time.ToString('HH:mm'))) detected, but no reboot found between them"
                $rebootCorrelation = @{
                    Event1800Time = $ev1800.Time
                    Event1799Time = $ev1799.Time
                    BootTimes     = @()
                    BootCount     = 0
                    Confirmed     = $false
                }
            }
        }
        
        return @{
            Status            = $status
            EventId           = $latestState.Id
            EventTime         = $latestState.Time
            EventMessage      = $msg
            AllEvents         = $parsedEvents
            EventSummary      = $eventSummary
            BucketId          = if ($bucketEvent) { $bucketEvent.BucketId } else { $null }
            Confidence        = if ($bucketEvent) { $bucketEvent.Confidence } else { $null }
            SkipReason        = if ($bucketEvent) { $bucketEvent.SkipReason } else { $null }
            RebootCorrelation = $rebootCorrelation
        }
    }
    
    # Helper function: Check for recent post-trigger events (1808, 1799) in last N minutes
    # Returns: 'Compliant' (1808 found), 'Pending1808' (1799 found, awaiting 1808),
    #          or 'Pending' (neither found yet)
    function Check-PostTriggerEvents {
        param (
            [int]$Minutes = 5
        )
        $startTime = (Get-Date).AddMinutes(-$Minutes)
        
        # Check for 1808 first (best case - already fully compliant)
        try {
            $ev1808 = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = 'Microsoft-Windows-TPM-WMI'
                Id           = 1808
                StartTime    = $startTime
            } -ErrorAction Stop
            if ($ev1808.Count -gt 0) { return 'Compliant' }
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                Write-Log "WARNING" "Failed to check for 1808: $($_.Exception.Message)"
            }
        }
        
        # Check for 1799 (boot manager installed, awaiting 1808)
        try {
            $ev1799 = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = 'Microsoft-Windows-TPM-WMI'
                Id           = 1799
                StartTime    = $startTime
            } -ErrorAction Stop
            if ($ev1799.Count -gt 0) { return 'Pending1808' }
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                Write-Log "WARNING" "Failed to check for 1799: $($_.Exception.Message)"
            }
        }
        
        return 'Pending'
    }
    
    # Helper function: Set the AvailableUpdates + MicrosoftUpdateManagedOptIn registry keys to trigger OS-side update
    # Helper function: Apply WinCS feature key if WinCsFlags.exe is available
    function Apply-WinCsFeatureKey {
        $winCsPath = "$env:SystemRoot\System32\WinCsFlags.exe"
        if (Test-Path $winCsPath) {
            try {
                & $winCsPath /apply --key "F33E0C8E002" | Out-Null
                Write-Log "SUCCESS" "Applied WinCS feature key F33E0C8E002 via WinCsFlags.exe"
                return $true
            }
            catch {
                Write-Log "ERROR" "Failed to apply WinCS key: $($_.Exception.Message)"
                return $false
            }
        }
        else {
            Write-Log "INFO" "WinCsFlags.exe not found; reg key should push this through still"
            return $false
        }
    }
    
    # Helper function: Trigger the Secure Boot update scheduled task
    function Trigger-SecureBootTask {
        try {
            Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update" -ErrorAction Stop
            Write-Log "SUCCESS" "Triggered Secure-Boot-Update scheduled task"
            return $true
        }
        catch {
            Write-Log "ERROR" "Failed to trigger Secure-Boot-Update task: $($_.Exception.Message)"
            return $false
        }
    }
    
    # Helper function: Check Secure Boot opt-in and telemetry configuration status (read-only)
    # Returns: hashtable with IsOptedIn, TelemetryMeetsMin, AvailableUpdatesSet, Summary,
    #          AvailableUpdatesPolicy, HighConfidenceOptOut, decoded bitmask meanings, and raw values
    function Check-OptInStatus {
        $dataCollectionPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        $secureBootPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        
        $allowTelemetry = (Get-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty "AllowTelemetry" -ErrorAction SilentlyContinue)
        $maxTelemetry   = (Get-ItemProperty -Path $dataCollectionPath -Name "MaxTelemetryAllowed" -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty "MaxTelemetryAllowed" -ErrorAction SilentlyContinue)
        $optIn          = (Get-ItemProperty -Path $secureBootPath -Name "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue)
        $available      = (Get-ItemProperty -Path $secureBootPath -Name "AvailableUpdates" -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty "AvailableUpdates" -ErrorAction SilentlyContinue)
        
        # AvailableUpdatesPolicy: GPO/MDM-driven persistent trigger (survives reboots, unlike AvailableUpdates)
        $availablePolicy = (Get-ItemProperty -Path $secureBootPath -Name "AvailableUpdatesPolicy" -ErrorAction SilentlyContinue |
                            Select-Object -ExpandProperty "AvailableUpdatesPolicy" -ErrorAction SilentlyContinue)
        
        # HighConfidenceOptOut: Opt-out flag for Microsoft's auto-deployment to high-confidence devices
        $highConfOptOut  = (Get-ItemProperty -Path $secureBootPath -Name "HighConfidenceOptOut" -ErrorAction SilentlyContinue |
                            Select-Object -ExpandProperty "HighConfidenceOptOut" -ErrorAction SilentlyContinue)
        
        # Telemetry meets minimum if AllowTelemetry >= 1 or is not set (OS default allows it)
        $telemetryMeetsMin = ($null -eq $allowTelemetry) -or ($allowTelemetry -ge 1)
        $isOptedIn         = $optIn -eq 0x5944
        $availableSet      = ($null -ne $available -and $available -ne 0)
        $policySet         = ($null -ne $availablePolicy -and $availablePolicy -ne 0)
        
        # Decode AvailableUpdates bitmask (use whichever is set; policy takes precedence)
        $effectiveAvailable = if ($policySet) { $availablePolicy } elseif ($availableSet) { $available } else { 0 }
        $availableMeaning   = if ($effectiveAvailable -ne 0) { Get-AvailableUpdatesMeaning -Value $effectiveAvailable } else { @() }
        
        # Determine summary
        if ($isOptedIn -and $telemetryMeetsMin) {
            $summary = 'Enabled'
        }
        elseif ($isOptedIn -and -not $telemetryMeetsMin) {
            $summary = 'Blocked'  # Opted in but telemetry too low
        }
        else {
            $summary = 'Not enabled'
        }
        
        return @{
            IsOptedIn              = $isOptedIn
            TelemetryMeetsMin      = $telemetryMeetsMin
            AvailableUpdatesSet    = $availableSet
            AllowTelemetry         = $allowTelemetry
            MaxTelemetry           = $maxTelemetry
            OptInValue             = $optIn
            AvailableUpdates       = $available
            AvailableUpdatesPolicy = $availablePolicy
            AvailableUpdatesPolicySet = $policySet
            HighConfidenceOptOut   = $highConfOptOut
            AvailableUpdatesMeaning = $availableMeaning
            EffectiveAvailable     = $effectiveAvailable
            Summary                = $summary
        }
    }
    
    # Helper function: Convert a Win32 or HRESULT error code to a message
    # Returns: string with the error message, or the hex code if unknown
    function Get-Win32ErrorMessage {
        param ([uint32]$ErrorCode)
        try {
            # Only low 16 bits matter for Win32Exception
            $win32 = $ErrorCode -band 0xFFFF
            $ex = [System.ComponentModel.Win32Exception]::new([int]$win32)
            return $ex.Message
        }
        catch {
            return ('0x{0:X}' -f $ErrorCode)
        }
    }
    
    # Helper function: Read Secure Boot servicing registry state
    # Returns: hashtable with UEFICA2023Status, Error, ErrorEvent, ErrorMessage, CanAttemptUpdateAfter
    # Source: HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing
    function Get-SecureBootServicingStatus {
        $servPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
        $attrPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes"
        
        $result = @{
            UEFICA2023Status           = $null
            WindowsUEFICA2023Capable   = $null   # 0=not in DB, 1=cert in DB, 2=cert in DB + booting from 2023 boot mgr
            UEFICA2023Error            = $null
            UEFICA2023ErrorHex         = $null
            UEFICA2023ErrorMessage     = $null
            UEFICA2023ErrorEvent       = $null
            UEFICA2023ErrorEventDesc   = $null
            CanAttemptUpdateAfter      = $null
            OEMManufacturerName        = $null
            OEMModelNumber             = $null
            FirmwareVersion            = $null
            FirmwareReleaseDate        = $null
        }
        
        # --- Servicing status ---
        $serv = Get-ItemProperty -Path $servPath -ErrorAction SilentlyContinue
        if ($null -ne $serv) {
            # UEFICA2023Status: "Updated" = compliant, other values = in progress or error
            if ($serv.PSObject.Properties.Match("UEFICA2023Status").Count -gt 0) {
                $result.UEFICA2023Status = $serv.UEFICA2023Status
            }
            
            # WindowsUEFICA2023Capable: 0=not in DB, 1=cert in DB, 2=cert in DB + booting from 2023 boot manager
            if ($serv.PSObject.Properties.Match("WindowsUEFICA2023Capable").Count -gt 0) {
                $result.WindowsUEFICA2023Capable = [int]$serv.WindowsUEFICA2023Capable
            }
            
            # UEFICA2023Error: Win32 error code from last failed attempt
            if ($serv.PSObject.Properties.Match("UEFICA2023Error").Count -gt 0 -and $null -ne $serv.UEFICA2023Error) {
                $rawError = [uint32]$serv.UEFICA2023Error
                $result.UEFICA2023Error = $rawError
                $result.UEFICA2023ErrorHex = ('0x{0:X}' -f $rawError)
                if ($rawError -ne 0) {
                    $result.UEFICA2023ErrorMessage = Get-Win32ErrorMessage -ErrorCode $rawError
                }
            }
            
            # UEFICA2023ErrorEvent: maps to the event ID that describes the failure
            if ($serv.PSObject.Properties.Match("UEFICA2023ErrorEvent").Count -gt 0 -and $null -ne $serv.UEFICA2023ErrorEvent) {
                $errorEvent = [int]$serv.UEFICA2023ErrorEvent
                $result.UEFICA2023ErrorEvent = $errorEvent
                $result.UEFICA2023ErrorEventDesc = if ($script:SecureBootEventDescriptions.ContainsKey($errorEvent)) {
                    $script:SecureBootEventDescriptions[$errorEvent]
                } else {
                    "Unknown event $errorEvent"
                }
            }
        }
        
        # --- Device attributes ---
        $attr = Get-ItemProperty -Path $attrPath -ErrorAction SilentlyContinue
        if ($null -ne $attr) {
            if ($attr.PSObject.Properties.Match("OEMManufacturerName").Count -gt 0)  { $result.OEMManufacturerName = $attr.OEMManufacturerName }
            if ($attr.PSObject.Properties.Match("OEMModelNumber").Count -gt 0)       { $result.OEMModelNumber = $attr.OEMModelNumber }
            if ($attr.PSObject.Properties.Match("FirmwareVersion").Count -gt 0)      { $result.FirmwareVersion = $attr.FirmwareVersion }
            if ($attr.PSObject.Properties.Match("FirmwareReleaseDate").Count -gt 0)  { $result.FirmwareReleaseDate = $attr.FirmwareReleaseDate }
            
            # CanAttemptUpdateAfter: FILETIME (byte[] or long) - next allowed update attempt
            if ($attr.PSObject.Properties.Match("CanAttemptUpdateAfter").Count -gt 0 -and $null -ne $attr.CanAttemptUpdateAfter) {
                try {
                    $raw = $attr.CanAttemptUpdateAfter
                    if ($raw -is [byte[]]) {
                        $filetime = [BitConverter]::ToInt64($raw, 0)
                    } else {
                        $filetime = [long]$raw
                    }
                    if ($filetime -gt 0) {
                        $result.CanAttemptUpdateAfter = [DateTime]::FromFileTime($filetime)
                    }
                }
                catch {
                    Write-Log "WARNING" "Could not convert CanAttemptUpdateAfter FILETIME to DateTime"
                }
            }
        }
        
        return $result
    }
    
    # Helper function: Decode AvailableUpdates bitmask into meanings
    # Source: Get-SecureBootCertInfo.ps1 (HorizonSecured) and MS KB5084567
    # Returns: array of strings describing each set bit
    function Get-AvailableUpdatesMeaning {
        param ([int]$Value)
        
        if ($Value -eq 0) {
            return @('No pending Secure Boot updates')
        }
        
        $meaning = @()
        
        # KEK special case: both bits set together
        if (($Value -band 0x4004) -eq 0x4004) { $meaning += 'KEK needs to be updated' }
        if ($Value -band 0x0004)               { $meaning += 'Install Microsoft KEK 2023 signed by OEM PK' }
        if ($Value -band 0x0040)               { $meaning += 'Apply Windows UEFI CA 2023 to DB' }
        if ($Value -band 0x0080)               { $meaning += 'Revoke PCA 2011 in DBX (Mitigation 3)' }
        if ($Value -band 0x0100)               { $meaning += 'Install boot manager signed with Windows UEFI CA 2023' }
        if ($Value -band 0x0200)               { $meaning += 'Apply SVN to DBX firmware (Mitigation 4)' }
        if ($Value -band 0x0800)               { $meaning += 'Apply Microsoft Option ROM UEFI CA 2023' }
        if ($Value -band 0x1000)               { $meaning += 'Apply Microsoft UEFI CA 2023' }
        # 0x4000 = conditional qualifier (apply only if UEFI CA 2011 trusted). This is always present (not displayed)
        
        # Detect undocumented bits
        $knownBits = 0x0004 -bor 0x0040 -bor 0x0080 -bor 0x0100 -bor 0x0200 -bor 0x0800 -bor 0x1000 -bor 0x4000 -bor 0x4004
        $unknownBits = $Value -band (-bnot $knownBits)
        if ($unknownBits -ne 0) {
            $meaning += ('Unknown update bits: 0x{0:X}' -f $unknownBits)
        }
        
        return $meaning
    }
    
    # Helper function: Find system boot events between two timestamps
    # Uses Kernel-General Event 12 (system startup marker) to detect reboots
    # Returns: @{ Found = $true/$false; BootTimes = @([datetime]...); Count = int }
    function Get-RebootsBetweenTimes {
        param (
            [Parameter(Mandatory)][datetime]$After,
            [Parameter(Mandatory)][datetime]$Before
        )
        $bootTimes = @()
        try {
            $boots = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = 'Microsoft-Windows-Kernel-General'
                Id           = 12
                StartTime    = $After
                EndTime      = $Before
            } -ErrorAction Stop
            $bootTimes = @($boots | ForEach-Object { $_.TimeCreated } | Sort-Object)
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                Write-Log "WARNING" "Failed to query boot events: $($_.Exception.Message)"
            }
        }
        return @{
            Found     = $bootTimes.Count -gt 0
            BootTimes = $bootTimes
            Count     = $bootTimes.Count
        }
    }
    
    # Helper function: Check if a system reboot is pending and return the source(s)
    # Returns: hashtable @{ Pending = $true/$false; Sources = @('Windows Update', 'Component Servicing') }
    function Get-PendingRebootStatus {
        $sources = @()
        
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $sources += 'Windows Update'
        }
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $sources += 'Component Servicing'
        }
        
        return @{
            Pending = $sources.Count -gt 0
            Sources = $sources
        }
    }
    
    # Helper function: Check if running as SYSTEM
    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY\*" -or $id.IsSystem
    }
    
    # Helper function: Set or create a registry value, retrying until correct
    function RegistryShouldBe {
        param(
            [Parameter(Mandatory)][string]$KeyPath,
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)]$Value,
            [ValidateSet('DWord','String','ExpandString','MultiString','Binary','QWord')]
            [string]$Type = 'DWord'
        )
        
        if (-not (Test-Path $KeyPath)) {
            try {
                New-Item -Path $KeyPath -Force | Out-Null
            }
            catch {
                Write-Log "ERROR" "Failed to create registry key for '$Name' at '$KeyPath': $_"
                return
            }
        }
        
        # --- Special-case Binary values to avoid noisy / unreliable array comparison ---
        if ($Type -eq 'Binary') {
            $current = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
                        
            if ($null -eq $current) {
                Write-Log "VERBOSE" "Creating $Name (Binary)"
                New-ItemProperty -Path $KeyPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
            }
            else {
                Write-Log "VERBOSE" "Updating $Name (Binary)"
                Set-ItemProperty -Path $KeyPath -Name $Name -Value $Value -Force
            }
            
            # Don’t fight PowerShell’s Binary comparison semantics here - treat as success
            Write-Log "VERBOSE" "$Name confirmed Binary value (length: $($Value.Length))"
            return
        }
        
        # --- Standard retry logic for non-Binary types ---
        function Test-RegistryValueEqual {
            param(
                $Current,
                $Desired
            )
            # For non-binary types, simple scalar comparison is fine
            return ($Current -ceq $Desired)
        }
        
        $attempt = 0
        do {
            $attempt++
            $current = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
            
            $valuesMatch = Test-RegistryValueEqual -Current $current -Desired $Value
            
            if (-not $valuesMatch) {
                if ($null -eq $current) {
                    Write-Log "VERBOSE" "Creating $Name = $Value"
                    New-ItemProperty -Path $KeyPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
                }
                else {
                    Write-Log "VERBOSE" "Updating $Name from $current to $Value"
                    Set-ItemProperty -Path $KeyPath -Name $Name -Value $Value -Force
                }
            }
            
            Start-Sleep -Milliseconds 800
            
            $current = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
            $valuesMatch = Test-RegistryValueEqual -Current $current -Desired $Value
            
        }
        while (-not $valuesMatch -and $attempt -lt 5)
        
        $final = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
                
        if (Test-RegistryValueEqual -Current $final -Desired $Value) {
            Write-Log "VERBOSE" "$Name confirmed $Value"
        }
        else {
            Write-Log "WARNING" "$Name failed to set to $Value"
        }
    }
    
    # Helper function: Retrieve user profiles and their NTUSER hive paths
    function Get-UserHive {
        [CmdletBinding()]
        param (
            [Parameter()]
            [ValidateSet('AzureAD', 'DomainAndLocal', 'All')]
            [String]$Type = "All",
            [Parameter()]
            [String[]]$ExcludedUsers,
            [Parameter()]
            [switch]$IncludeDefault
        )
        
        $Patterns = switch ($Type) {
            "AzureAD"        { "S-1-12-1-(\d+-?){4}$" }
            "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
            "All"            { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" }
        }
        
        $UserProfiles = foreach ($Pattern in $Patterns) {
            Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
                Where-Object { $_.PSChildName -match $Pattern } |
                Select-Object @{
                    Name       = "SID"
                    Expression = { $_.PSChildName }
                }, @{
                    Name       = "Username"
                    Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" }
                }, @{
                    Name       = "Domain"
                    Expression = {
                        if ($_.PSChildName -match "S-1-12-1-(\d+-?){4}$") { "AzureAD" } else { $null }
                    }
                }, @{
                    Name       = "UserHive"
                    Expression = { "$($_.ProfileImagePath)\NTUSER.DAT" }
                }, @{
                    Name       = "Path"
                    Expression = { $_.ProfileImagePath }
                }
        }
        
        if ($IncludeDefault) {
            $DefaultProfile = "" | Select-Object Username, SID, UserHive, Path, Domain
            $DefaultProfile.Username = "Default"
            $DefaultProfile.Domain   = $env:COMPUTERNAME
            $DefaultProfile.SID      = "DefaultProfile"
            $DefaultProfile.UserHive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
            $DefaultProfile.Path     = "$env:SystemDrive\Users\Default"
            
            $UserProfiles = @($UserProfiles) + @(
                $DefaultProfile | Where-Object { $ExcludedUsers -notcontains $_.Username }
            )
        }
        
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            $AllAccounts = Get-WmiObject -Class "win32_UserAccount"
        }
        else {
            $AllAccounts = Get-CimInstance -ClassName "win32_UserAccount"
        }
        
        $CompleteUserProfiles = $UserProfiles | ForEach-Object {
            $SID         = $_.SID
            $Win32Object = $AllAccounts | Where-Object { $_.SID -like $SID }
            
            if ($Win32Object) {
                $Win32Object | Add-Member -NotePropertyName UserHive -NotePropertyValue $_.UserHive -Force
                $Win32Object | Add-Member -NotePropertyName Path     -NotePropertyValue $_.Path     -Force
                $Win32Object
            }
            else {
                [PSCustomObject]@{
                    Name     = $_.Username
                    Domain   = $_.Domain
                    SID      = $_.SID
                    UserHive = $_.UserHive
                    Path     = $_.Path
                }
            }
        }
        
        $CompleteUserProfiles | Where-Object { $ExcludedUsers -notcontains $_.Name }
    }
    
    # Helper function: Enable required telemetry for Windows Update Secure Boot management
    # Sets machine-level AllowTelemetry + MaxTelemetryAllowed, and per-user ShowedToastAtLevel
    function Enable-RequiredTelemetry {
        Write-Log "INFO" "Setting telemetry to minimum 'Required' level for Secure Boot management"
        
        $dataCollectionPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        
        # Machine-level: AllowTelemetry = 1 (Required), unless already >= 3 (Full)
        $currentAllow = (Get-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue |
                         Select-Object -ExpandProperty "AllowTelemetry" -ErrorAction SilentlyContinue)
        if ($currentAllow -ge 3) {
            Write-Log "INFO" "AllowTelemetry already set to $currentAllow (optional+required); skipping"
        }
        else {
            RegistryShouldBe -KeyPath $dataCollectionPath -Name "AllowTelemetry" -Value 1
        }
        
        # Machine-level: MaxTelemetryAllowed = 1 (Required), unless already >= 3
        $currentMax = (Get-ItemProperty -Path $dataCollectionPath -Name "MaxTelemetryAllowed" -ErrorAction SilentlyContinue |
                       Select-Object -ExpandProperty "MaxTelemetryAllowed" -ErrorAction SilentlyContinue)
        if ($currentMax -ge 3) {
            Write-Log "INFO" "MaxTelemetryAllowed already set to $currentMax (optional+required); skipping"
        }
        else {
            RegistryShouldBe -KeyPath $dataCollectionPath -Name "MaxTelemetryAllowed" -Value 1
        }
        
        # Per-user: ShowedToastAtLevel = 1 across all user hives
        Write-Log "INFO" "Retrieving user profiles for per-user telemetry keys"
        $isSystem = Test-IsSystem
        
        if ($isSystem) {
            $hives = Get-UserHive -Type 'All' -IncludeDefault:([bool]$IncludeDefaultHive)
        }
        else {
            Write-Log "INFO" "Not running as SYSTEM; applying per-user key for current user only"
            $hives = @(
                [PSCustomObject]@{
                    Name     = $env:USERNAME
                    Domain   = $env:USERDOMAIN
                    SID      = 'CurrentUser'
                    UserHive = $null
                    Path     = $env:USERPROFILE
                }
            )
        }
        
        $loaded = @()
        
        foreach ($hive in $hives) {
            $sid      = $hive.SID
            $userHive = $hive.UserHive
            $label    = if ($hive.Name) { $hive.Name } else { $sid }
            
            if ($isSystem -and $sid -ne 'CurrentUser') {
                $regRoot = "HKEY_USERS\$sid"
                
                # Load hive if not mounted
                if (-not (Test-Path "Registry::$regRoot")) {
                    if ($userHive -and (Test-Path $userHive)) {
                        try {
                            Write-Log "VERBOSE" "Loading hive for $label"
                            reg.exe LOAD "HKEY_USERS\$sid" "$userHive" 2>&1 | Out-Null
                            $loaded += $sid
                        }
                        catch {
                            Write-Log "WARNING" "Failed to load hive for $label. Skipping."
                            continue
                        }
                    }
                    else {
                        Write-Log "WARNING" "Hive file not found for $label. Skipping."
                        continue
                    }
                }
                
                $diagPath = "Registry::$regRoot\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"
            }
            else {
                $diagPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"
            }
            
            # ShowedToastAtLevel: skip if already >= 3
            $currentToast = (Get-ItemProperty -Path $diagPath -Name "ShowedToastAtLevel" -ErrorAction SilentlyContinue |
                             Select-Object -ExpandProperty "ShowedToastAtLevel" -ErrorAction SilentlyContinue)
            if ($currentToast -ge 3) {
                Write-Log "INFO" "ShowedToastAtLevel for $label already $currentToast; skipping"
            }
            else {
                Write-Log "INFO" "Setting ShowedToastAtLevel for $label"
                RegistryShouldBe -KeyPath $diagPath -Name "ShowedToastAtLevel" -Value 1
            }
        }
        
        # Unload any hives that were loaded
        if ($loaded.Count -gt 0) {
            foreach ($sid in $loaded) {
                [gc]::Collect()
                Start-Sleep -Seconds 1
                try {
                    Start-Process -FilePath "cmd.exe" `
                                -ArgumentList "/C reg.exe UNLOAD HKU\$sid" `
                                -Wait -WindowStyle Hidden -ErrorAction Stop | Out-Null
                    Write-Log "VERBOSE" "Unloaded hive for $sid"
                }
                catch {
                    Write-Log "WARNING" "Failed to unload hive for $sid. $_"
                }
            }
        }
        
        Write-Log "SUCCESS" "Required telemetry configuration complete"
    }
    
    # Helper function: Remove telemetry enforcement keys (restore to OS defaults)
    function Remove-TelemetryEnforcement {
        Write-Log "INFO" "Removing telemetry enforcement keys (restoring to OS defaults)"
        
        $dataCollectionPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        
        if (Test-Path $dataCollectionPath) {
            $collectionKey = Get-ItemProperty -Path $dataCollectionPath -ErrorAction SilentlyContinue
            
            if ($collectionKey.AllowTelemetry) {
                try {
                    Remove-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -ErrorAction Stop
                    Write-Log "SUCCESS" "Removed AllowTelemetry enforcement"
                }
                catch {
                    Write-Log "ERROR" "Failed to remove AllowTelemetry: $($_.Exception.Message)"
                }
            }
            else {
                Write-Log "INFO" "AllowTelemetry not present; nothing to remove"
            }
            
            if ($collectionKey.MaxTelemetryAllowed) {
                try {
                    Remove-ItemProperty -Path $dataCollectionPath -Name "MaxTelemetryAllowed" -ErrorAction Stop
                    Write-Log "SUCCESS" "Removed MaxTelemetryAllowed enforcement"
                }
                catch {
                    Write-Log "ERROR" "Failed to remove MaxTelemetryAllowed: $($_.Exception.Message)"
                }
            }
            else {
                Write-Log "INFO" "MaxTelemetryAllowed not present; nothing to remove"
            }
        }
        
        Write-Log "INFO" "Per-user ShowedToastAtLevel keys left as-is (default value is 1; no enforcement to remove)"
    }
    
    # Helper function: Set the Secure Boot opt-in gate key (MicrosoftUpdateManagedOptIn only)
    # Does NOT write AvailableUpdates - stage pushing is handled by EnforceSvnCompliance
    function Set-SecureBootOptInKeys {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        $optInValue = 0x5944  # Microsoft Update managed opt-in magic value
        
        try {
            Write-Log "INFO" "Setting Secure Boot opt-in key (MicrosoftUpdateManagedOptIn)"
            RegistryShouldBe -KeyPath $regPath -Name "MicrosoftUpdateManagedOptIn" -Value $optInValue
            Write-Log "SUCCESS" "Secure Boot opt-in key set (MicrosoftUpdateManagedOptIn = 0x5944)"
            return $true
        }
        catch {
            Write-Log "ERROR" "Failed to set opt-in key: $($_.Exception.Message)"
            return $false
        }
    }
    
    # Helper function: Remove the Secure Boot opt-in gate (opt out of Windows Update management)
    # Does NOT remove AvailableUpdates - already-triggered updates should complete
    function Remove-SecureBootOptInKeys {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        
        $currentOptIn = (Get-ItemProperty -Path $regPath -Name "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue |
                         Select-Object -ExpandProperty "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue)
        
        if ($currentOptIn) {
            try {
                Remove-ItemProperty -Path $regPath -Name "MicrosoftUpdateManagedOptIn" -ErrorAction Stop
                Write-Log "SUCCESS" "Removed MicrosoftUpdateManagedOptIn (opted out of Windows Update Secure Boot management)"
            }
            catch {
                Write-Log "ERROR" "Failed to remove MicrosoftUpdateManagedOptIn: $($_.Exception.Message)"
            }
        }
        else {
            Write-Log "INFO" "MicrosoftUpdateManagedOptIn not present; already opted out"
        }
        
        Write-Log "INFO" "AvailableUpdates left as-is (already-triggered updates should complete)"
    }
    
    # Legacy wrappers - delegate to unified Get-OemGuide function
    function Get-OemKeyResetGuide  { return Get-OemGuide -GuideType 'KeyReset' }
    function Get-OemBIOSUpdateGuide { return Get-OemGuide -GuideType 'BIOSUpdate' }
    
    # =======================================================================
    # SVN Stage Prerequisites Check (Test-SvnStagePrerequisites)
    # =======================================================================
    # GATE for Mitigation 3+4. Stage 1 + Stage 2 must be VERIFIED complete.
    # Used by Invoke-SvnEnforcement (gate) and Repair-SvnEnforcement (fix).
    #
    # Stage 1 (Mitigation 1 / 0x40): Add Windows UEFI CA 2023 to DB
    #   - Ground truth: $Has2023InDb (direct UEFI db read after 30s wait)
    #   - Manifest:     0x40 bit must be consumed (no longer in AvailableUpdates)
    #   - BOTH must pass: cert physically present AND OS finished processing
    #
    # Stage 2 (Mitigation 2 / 0x100): Install 2023-signed boot manager
    #   - Ground truth: Event 1799 (boot manager installed) or 1808 (compliant)
    #   - Manifest:     0x100 bit must be consumed (no longer in AvailableUpdates)
    #   - BOTH must pass: event confirmed AND OS finished processing
    #   - "Applied" status alone is NOT sufficient as it only means triggered
    #
    # Reboot check:
    #   - Event 1800 = cert deployment still in progress, reboot needed
    #   - Unverified Mitigation 2 (triggered but no 1799/1808) = treat as reboot needed
    #   - $CertStatus may predate enforcement, so 1800 is re-checked post-trigger
    #
    # ALL checks must pass. If ANY fails, Mitigation 3+4 are blocked.
    #
    # Returns hashtable: Stage1Done, Stage2Done, RebootPending, AllPrereqsMet,
    #   Stage3/4Applied (1037/1042 events), Stage3/4BitPending (0x80/0x200 in
    #   manifest), CurrentManifest, BlockReason.
    # =======================================================================
    function Test-SvnStagePrerequisites {
        param (
            [bool]$Has2023InDb,
            [hashtable]$CertStatus,
            [hashtable]$SvnEnforcementResult   # Optional - only set during active enforcement
        )
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        
        # --- Event checks ---
        $has1799 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1799)
        $has1808 = ($null -ne $CertStatus -and $CertStatus.EventId -eq 1808)
        $has1037 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1037)
        $has1042 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1042)
        $has1800 = ($null -ne $CertStatus -and $CertStatus.EventId -eq 1800)
        
        # --- Manifest checks ---
        $currentAv = (Get-ItemProperty -Path $regPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                       Select-Object -ExpandProperty 'AvailableUpdates' -ErrorAction SilentlyContinue)
        if ($null -eq $currentAv) { $currentAv = 0 }
        
        $stage1BitPending = ($currentAv -band 0x0040) -ne 0   # DB cert (0x40) still in manifest
        $stage2BitPending = ($currentAv -band 0x0100) -ne 0   # Boot manager (0x100) still in manifest
        $stage3BitPending = ($currentAv -band 0x0080) -ne 0   # 2011 revocation (0x80) in manifest
        $stage4BitPending = ($currentAv -band 0x0200) -ne 0   # SVN update (0x200) in manifest
        
        # --- Stage 1: 2023 cert in UEFI db ---
        # 1808 = fully compliant (cert + boot mgr + booting from it) - overrides manifest bit
        $stage1Done = $Has2023InDb -and (-not $stage1BitPending -or $has1808)
        $stage1Detail = if (-not $Has2023InDb) { 'Cert not in db' }
                        elseif ($stage1BitPending -and -not $has1808) { 'Cert in db but 0x40 still pending in manifest' }
                        else { 'Complete' }
        
        # --- Stage 2: Boot manager confirmed via event ---
        $bootMgrConfirmed = ($has1799 -or $has1808)
        # 1808 = definitive confirmation, overrides manifest bit still pending
        $stage2Done = $bootMgrConfirmed -and (-not $stage2BitPending -or $has1808)
        $stage2Detail = if (-not $bootMgrConfirmed) { 'No 1799/1808 event (boot manager unconfirmed)' }
                        elseif ($stage2BitPending -and -not $has1808) { 'Event confirmed but 0x100 still pending in manifest' }
                        else { 'Complete' }
        
        # --- Reboot pending ---
        $rebootPending = $has1800
        if (-not $rebootPending -and $null -ne $SvnEnforcementResult -and $SvnEnforcementResult.Mitigation2 -eq 'Applied') {
            # Mitigation 2 was just triggered - if no confirmation event, treat as reboot pending
            $rebootPending = (-not $has1799 -and -not $has1808)
        }
        
        # --- Stage 3+4 status ---
        $stage3Applied = $has1037
        $stage4Applied = $has1042
        
        # When stages 1+2 are done, a pending reboot is for stage 3+4 progression (not a blocker).
        # Only treat reboot as blocking when stages 1 or 2 are still incomplete.
        $rebootBlocks = $rebootPending -and (-not $stage1Done -or -not $stage2Done)
        
        return @{
            Stage1Done        = $stage1Done
            Stage1Detail      = $stage1Detail
            Stage2Done        = $stage2Done
            Stage2Detail      = $stage2Detail
            RebootPending     = $rebootPending
            AllPrereqsMet     = ($stage1Done -and $stage2Done -and -not $rebootBlocks)
            Stage3Applied     = $stage3Applied      # 1037 event = DBX already modified
            Stage4Applied     = $stage4Applied      # 1042 event = SVN already in DBX
            Stage3BitPending  = $stage3BitPending   # 0x80 in manifest but no 1037 yet
            Stage4BitPending  = $stage4BitPending   # 0x200 in manifest but no 1042 yet
            CurrentManifest   = $currentAv
            BlockReason       = if ($rebootBlocks) { 'Reboot required to complete stages 1-2' }
                                elseif (-not $stage1Done) { $stage1Detail }
                                elseif (-not $stage2Done) { $stage2Detail }
                                else { $null }
        }
    }
    
    # =======================================================================
    # SVN Enforcement Repair Function
    # =======================================================================
    # Checks if Stage 3+4 mitigations were prematurely triggered (before Stage
    # 1+2 were verified complete) and attempts to clear the pending bits from
    # AvailableUpdates before they are processed on the next reboot.
    #
    # REVERSIBILITY:
    #   - If 1037/1042 have NOT fired: bits 0x80/0x200 can be cleared from the
    #     registry. The scheduled task won't process them. DBX is untouched.
    #   - If 1037/1042 HAVE fired: DBX has already been modified. The only
    #     recovery is a BIOS "Restore Factory Keys" (OEM-dependent, removes
    #     all security protections). Cannot be done programmatically.
    #     Uses Get-OemKeyResetGuide to provide OEM-specific BIOS instructions.
    #
    # Source: KB5025885 - "After the mitigation is enabled on a device, it
    #   cannot be reverted if you continue to use Secure Boot on that device."
    # Source: Enterprise Deployment Guidance for CVE-2023-24932 - "If
    #   Mitigations 3 and/or 4 have been applied and the DBX is cleared,
    #   then reapplying mitigations 3 and/or 4 will be necessary."
    # =======================================================================
    function Repair-SvnEnforcement {
        param (
            [bool]$Has2023InDb,
            [hashtable]$CertStatus
        )
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        
        $result = [ordered]@{
            Action          = 'None'
            BitsCleared     = @()
            BitsFailed      = @()
            IrreversibleDbx = @()
            Detail          = ''
            OemKeyResetGuide = $null
            RebootAdvised   = $false
        }
        
        # Check prerequisites
        $prereqs = Test-SvnStagePrerequisites -Has2023InDb $Has2023InDb -CertStatus $CertStatus
        
        if ($prereqs.AllPrereqsMet) {
            $result.Action = 'None'
            $result.Detail = 'Stage 1+2 prerequisites are met. No repair needed.'
            Write-Log "INFO" "SVN Repair: Prerequisites met - no repair needed"
            return $result
        }
        
        # Check what Stage 3+4 state is in
        $needsRepair = $false
        
        # Stage 3: Check if 0x80 was set prematurely
        if ($prereqs.Stage3Applied) {
            # Event 1037 fired - DBX already modified, cannot undo from Windows
            $result.IrreversibleDbx += 'Mitigation 3 (PCA 2011 revocation in DBX - Event 1037 confirmed)'
            Write-Log "WARNING" "SVN Repair: Mitigation 3 already applied to DBX (Event 1037). Cannot revert from Windows."
            $needsRepair = $true
        }
        elseif ($prereqs.Stage3BitPending) {
            # 0x80 in manifest but no 1037 - can clear the bit before next reboot
            $needsRepair = $true
        }
        
        # Stage 4: Check if 0x200 was set prematurely
        if ($prereqs.Stage4Applied) {
            # Event 1042 fired - SVN already in DBX, cannot undo from Windows
            $result.IrreversibleDbx += 'Mitigation 4 (SVN update in DBX - Event 1042 confirmed)'
            Write-Log "WARNING" "SVN Repair: Mitigation 4 already applied to DBX (Event 1042). Cannot revert from Windows."
            $needsRepair = $true
        }
        elseif ($prereqs.Stage4BitPending) {
            # 0x200 in manifest but no 1042 - can clear the bit before next reboot
            $needsRepair = $true
        }
        
        if (-not $needsRepair) {
            $result.Action = 'None'
            $result.Detail = 'No Stage 3+4 bits pending or applied. Nothing to repair.'
            Write-Log "INFO" "SVN Repair: No Stage 3+4 activity detected"
            return $result
        }
        
        # Attempt to clear pending bits (only those not yet applied to DBX)
        $currentAv = $prereqs.CurrentManifest
        $bitsToRemove = 0
        
        if ($prereqs.Stage3BitPending -and -not $prereqs.Stage3Applied) {
            $bitsToRemove = $bitsToRemove -bor 0x0080
            Write-Log "INFO" "SVN Repair: Will clear Mitigation 3 bit (0x80) - not yet applied to DBX"
        }
        if ($prereqs.Stage4BitPending -and -not $prereqs.Stage4Applied) {
            $bitsToRemove = $bitsToRemove -bor 0x0200
            Write-Log "INFO" "SVN Repair: Will clear Mitigation 4 bit (0x200) - not yet applied to DBX"
        }
        
        if ($bitsToRemove -ne 0) {
            $newAv = $currentAv -band (-bnot $bitsToRemove)
            $oldHex = '0x{0:X}' -f $currentAv
            $newHex = '0x{0:X}' -f $newAv
            $removedHex = '0x{0:X}' -f $bitsToRemove
            Write-Log "INFO" "SVN Repair: Clearing bits $removedHex from AvailableUpdates ($oldHex -> $newHex)"
            
            try {
                Set-ItemProperty -Path $regPath -Name 'AvailableUpdates' -Value $newAv -Type DWord -Force
                # Verify the write
                $verifyAv = (Get-ItemProperty -Path $regPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                              Select-Object -ExpandProperty 'AvailableUpdates' -ErrorAction SilentlyContinue)
                if ($verifyAv -eq $newAv) {
                    Write-Log "SUCCESS" "SVN Repair: AvailableUpdates updated to $newHex (verified)"
                    if ($bitsToRemove -band 0x0080) { $result.BitsCleared += 'Mitigation 3 (0x80 - PCA 2011 revocation)' }
                    if ($bitsToRemove -band 0x0200) { $result.BitsCleared += 'Mitigation 4 (0x200 - SVN update)' }
                    $result.Action = 'BitsCleared'
                    $result.RebootAdvised = $true
                }
                else {
                    Write-Log "ERROR" "SVN Repair: Verification failed - AvailableUpdates is 0x$($verifyAv.ToString('X')), expected $newHex"
                    if ($bitsToRemove -band 0x0080) { $result.BitsFailed += 'Mitigation 3 (0x80)' }
                    if ($bitsToRemove -band 0x0200) { $result.BitsFailed += 'Mitigation 4 (0x200)' }
                    $result.Action = 'Failed'
                }
            }
            catch {
                Write-Log "ERROR" "SVN Repair: Failed to update AvailableUpdates: $($_.Exception.Message)"
                if ($bitsToRemove -band 0x0080) { $result.BitsFailed += 'Mitigation 3 (0x80)' }
                if ($bitsToRemove -band 0x0200) { $result.BitsFailed += 'Mitigation 4 (0x200)' }
                $result.Action = 'Failed'
            }
        }
        
        # Build summary
        $detailParts = @()
        if ($result.BitsCleared.Count -gt 0) {
            $detailParts += "Cleared pending bits: $($result.BitsCleared -join '; ')"
        }
        if ($result.BitsFailed.Count -gt 0) {
            $detailParts += "Failed to clear: $($result.BitsFailed -join '; ')"
        }
        if ($result.IrreversibleDbx.Count -gt 0) {
            $detailParts += "IRREVERSIBLE (already in DBX): $($result.IrreversibleDbx -join '; ')"
            $detailParts += 'Recovery requires a BIOS Secure Boot key reset (Restore Factory Keys)'
            # Look up OEM-specific key reset guide
            $oemGuide = Get-OemKeyResetGuide
            if ($oemGuide) {
                $result.OemKeyResetGuide = $oemGuide
                $detailParts += "OEM Key Reset Guide: $oemGuide"
                Write-Log "INFO" "SVN Repair: OEM key reset guide available: $oemGuide"
            }
            else {
                $detailParts += 'No OEM-specific key reset guide found. Check BIOS setup for "Restore Factory Keys" or "Reset Secure Boot Keys".'
            }
            Write-Log "ERROR" "SVN Repair: DBX modifications are irreversible from Windows. BIOS Secure Boot key reset required."
        }
        $detailParts += "Prerequisites not met: $($prereqs.BlockReason)"
        $result.Detail = $detailParts -join '. '
        
        Write-Log "INFO" "SVN Repair result: $($result.Detail)"
        return $result
    }
    
    # =======================================================================
    # SVN BITLOCKER SAFETY BOUNDARY
    # =======================================================================
    # Runs only when Stage 3 and/or Stage 4 will be newly triggered or their
    # manifest bits are already pending reboot. Stages 1/2 and Passive/Audit runs
    # without pending Stage 3/4 bits do not enter this function. Volume selection is
    # aligned with the requested SVN safety scope: OS and fixed-data volumes
    # are handled (including USB-connected FixedData); removable volumes are excluded.
    function New-SvnBitLockerSafetyResult {
        param (
            [bool]$Enabled = $true,
            [ValidateRange(1,15)]
            [int]$RebootCount = 2,
            [string[]]$Stages = @()
        )

        return [ordered]@{
            Status                  = 'NotRequired'
            Enabled                 = $Enabled
            RebootCount             = $RebootCount
            Stages                  = @($Stages)
            EligibleVolumes         = @()
            SuspendedVolumes        = @()
            AlreadySuspendedVolumes = @()
            SkippedVolumes          = @()
            FailedVolumes           = @()
            CanProceed              = $true
            PendingManifest         = $false
            UnsafePendingManifest   = $false
        }
    }
    
    function Suspend-SystemBitLockerVolumesForSvn {
        param (
            [bool]$Enabled = $true,
            [ValidateRange(1,15)]
            [int]$RebootCount = 2,
            [string[]]$Stages = @()
        )
        
        $result = New-SvnBitLockerSafetyResult -Enabled $Enabled -RebootCount $RebootCount -Stages $Stages
        
        Write-Host "`n ==================================================================="
        Write-Host " ===       SVN Stage 3/4 BitLocker Safety Boundary               ==="
        Write-Host " ==================================================================="
        Write-Log "INFO" "SVN BitLocker safety requested for $($Stages -join ' + ') (two-reboots)"
        
        if (-not $Enabled) {
            $result.Status = 'Disabled'
            Write-Log "WARNING" "SuspendBitlockerForSVN is Disabled; continuing without automatic suspension"
            return $result
        }
        
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) -or
            -not (Get-Command Suspend-BitLocker -ErrorAction SilentlyContinue)) {
            $result.Status = 'Failed'
            $result.CanProceed = $false
            $result.FailedVolumes += 'BitLocker PowerShell cmdlets unavailable'
            Write-Log "ERROR" "Cannot verify or suspend BitLocker volumes; Stage 3/4 trigger is blocked"
            return $result
        }
        
        try {
            $allVolumes = @(Get-BitLockerVolume -ErrorAction Stop)
        }
        catch {
            $result.Status = 'Failed'
            $result.CanProceed = $false
            $result.FailedVolumes += "Volume enumeration failed: $($_.Exception.Message)"
            Write-Log "ERROR" "Failed to enumerate BitLocker volumes: $($_.Exception.Message)"
            return $result
        }
        
        $systemVolumes = @($allVolumes | Where-Object {
            ([string]$_.VolumeType) -in @('OperatingSystem','FixedData')
        })
        
        foreach ($volume in $systemVolumes) {
            $mountPoint       = [string]$volume.MountPoint
            $volumeStatus     = [string]$volume.VolumeStatus
            $protectionStatus = [string]$volume.ProtectionStatus
            
            if ($volumeStatus -eq 'FullyDecrypted') {
                if (-not [string]::IsNullOrWhiteSpace($mountPoint)) {
                    $result.SkippedVolumes += "$mountPoint (not encrypted)"
                }
                continue
            }
            
            if ([string]::IsNullOrWhiteSpace($mountPoint)) {
                $result.FailedVolumes += '<unmounted encrypted system volume>'
                Write-Log "ERROR" "Found an encrypted internal BitLocker volume without a mount point; cannot suspend it"
                continue
            }
            
            $result.EligibleVolumes += $mountPoint
            
            if ($volumeStatus -eq 'EncryptionInProgress') {
                $result.FailedVolumes += "$mountPoint (encryption in progress)"
                Write-Log "ERROR" "Cannot suspend $mountPoint while BitLocker encryption is in progress"
                continue
            }
            
            if ($protectionStatus -in @('Off','Suspended')) {
                $result.AlreadySuspendedVolumes += $mountPoint
                Write-Log "INFO" "BitLocker protection is already suspended on $mountPoint; existing suspension left in place"
                continue
            }
            
            if ($protectionStatus -ne 'On') {
                $result.FailedVolumes += "$mountPoint (protection status: $protectionStatus)"
                Write-Log "ERROR" "Cannot safely classify BitLocker protection on $mountPoint (status: $protectionStatus)"
                continue
            }
            
            try {
                Suspend-BitLocker -MountPoint $mountPoint -RebootCount $RebootCount -Confirm:$false -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                $refreshed = Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
                if ([string]$refreshed.ProtectionStatus -notin @('Off','Suspended')) {
                    throw "Protection status remained $($refreshed.ProtectionStatus) after Suspend-BitLocker"
                }
                $result.SuspendedVolumes += $mountPoint
                Write-Log "SUCCESS" "BitLocker suspended on $mountPoint for $RebootCount reboots"
            }
            catch {
                $result.FailedVolumes += "$mountPoint ($($_.Exception.Message))"
                Write-Log "ERROR" "Failed to suspend BitLocker on ${mountPoint}: $($_.Exception.Message)"
            }
        }
        
        if ($result.FailedVolumes.Count -gt 0) {
            $result.Status = 'Failed'
            $result.CanProceed = $false
            Write-Log "ERROR" "BitLocker suspension failed for one or more system volumes; a new Stage 3/4 trigger will not be written"
        }
        elseif ($result.SuspendedVolumes.Count -gt 0 -and $result.AlreadySuspendedVolumes.Count -gt 0) {
            $result.Status = 'SuspendedWithExisting'
        }
        elseif ($result.SuspendedVolumes.Count -gt 0) {
            $result.Status = 'Suspended'
        }
        elseif ($result.AlreadySuspendedVolumes.Count -gt 0) {
            $result.Status = 'AlreadySuspended'
        }
        else {
            $result.Status = 'NoProtectedVolumes'
            Write-Log "INFO" "No encrypted internal BitLocker volumes require suspension"
        }
        
        return $result
    }
    
    # =======================================================================
    # END SVN BITLOCKER SAFETY BOUNDARY
    # =======================================================================
    
    # =======================================================================
    # SVN Enforcement Function
    # =======================================================================
    # Applies the KB5025885 Secure Boot hardening mitigations (CVE-2023-24932 enterprise deployment guidance).
    # Each mitigation is a specific AvailableUpdates bitmask value + scheduled task trigger.
    # The function is idempotent - it checks current state before each step and skips
    # mitigations that have already been applied.
    #
    # Mitigation 1 (0x40)  : Add Windows UEFI CA 2023 cert to DB
    # Mitigation 2 (0x100) : Install 2023-signed boot manager
    # Mitigation 3 (0x80)  : Revoke PCA 2011 in DBX - blocks old boot managers
    # Mitigation 4 (0x200) : Apply SVN update to firmware DBX - prevents rollback
    #
    # Combined Mitigation 3+4 (0x280) per CVE-2023-24932 enterprise guidance - single reboot.
    #
    # Source: https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d
    # Source: https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967
    # =======================================================================
    function Invoke-SvnEnforcement {
        param (
            [bool]$Has2023InDb,
            [bool]$Has2023InKek,
            [hashtable]$SvnStatus,
            [hashtable]$CertStatus,
            [byte[]]$DbxBytes,
            [array]$Ca2011RevokedInDbx,
            [string[]]$DbCertsFound = @(),
            [bool]$SuspendBitlockerForSVN = $true,
            $InitialBitLockerSuspension = $null
        )
        
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        $initialSafetyResult = if ($null -ne $InitialBitLockerSuspension) {
            $InitialBitLockerSuspension
        }
        else {
            New-SvnBitLockerSafetyResult -Enabled $SuspendBitlockerForSVN -RebootCount 2
        }
        $results = [ordered]@{
            Mitigation1 = $null   # DB cert
            Mitigation2 = $null   # Boot manager
            Mitigation3 = $null   # 2011 revocation
            Mitigation4 = $null   # SVN update
            Mitigation1BlockedReason = $null
            Mitigation2BlockedReason = $null
            Mitigation3BlockedReason = $null
            Mitigation4BlockedReason = $null
            RebootRequired = $false
            SupplementaryCertsAttempted = $false
            ActionsApplied = @()
            ActionsSkipped = @()
            BitLockerSuspension = $initialSafetyResult
        }

        # A pre-existing Stage 3/4 manifest is evaluated before this function is
        # called. If BitLocker preparation failed, do not trigger any Secure Boot
        # task: it could process those already-pending irreversible bits.
        if ($results.BitLockerSuspension.PendingManifest -and
            ($results.BitLockerSuspension.UnsafePendingManifest -or -not $results.BitLockerSuspension.CanProceed)) {
            $preflightBlockReason = if ($results.BitLockerSuspension.UnsafePendingManifest) {
                'Stage 1/2 prerequisites incomplete and pending Stage 3/4 bits could not be cleared'
            }
            else {
                'BitLocker suspension failed; pending Stage 3/4 bits must not be processed'
            }
            if (@($results.BitLockerSuspension.Stages) -contains 'Stage 3') {
                $results.Mitigation3 = 'Blocked'
                $results.Mitigation3BlockedReason = $preflightBlockReason
                $results.ActionsSkipped += 'Mitigation 3 (pending manifest; safety preflight blocked)'
            }
            if (@($results.BitLockerSuspension.Stages) -contains 'Stage 4') {
                $results.Mitigation4 = 'Blocked'
                $results.Mitigation4BlockedReason = $preflightBlockReason
                $results.ActionsSkipped += 'Mitigation 4 (pending manifest; safety preflight blocked)'
            }
            $results.RebootRequired = $true
            Write-Log "ERROR" "SVN Enforcement stopped before task trigger: $preflightBlockReason. DO NOT REBOOT."
            return $results
        }
        
        # --- Pre-flight: trigger scheduled task to capture post-reboot events ---
        # After a reboot, events like 1799 (boot manager installed) only appear once the
        # Secure-Boot-Update task runs. Trigger it now so mitigation evaluation sees current state.
        Write-Log "INFO" "SVN Enforcement: Triggering scheduled task to capture post-reboot events"
        $null = Trigger-SecureBootTask
        Start-Sleep -Seconds 10
        # Re-query events so mitigation checks see any newly-fired events (e.g. 1799 after reboot)
        $postBootStatus = Get-CertUpdateEventStatus
        if ($null -ne $postBootStatus -and $null -ne $postBootStatus.AllEvents) {
            $preEventCount = if ($null -ne $CertStatus -and $null -ne $CertStatus.AllEvents) { $CertStatus.AllEvents.Count } else { 0 }
            if ($postBootStatus.AllEvents.Count -gt $preEventCount) {
                Write-Log "INFO" "SVN Enforcement: Post-boot event refresh found $($postBootStatus.AllEvents.Count) events (was $preEventCount)"
                $CertStatus = $postBootStatus
            }
        }
        
        # --- Pre-flight checks ---
        Write-Log "INFO" "SVN Enforcement: Evaluating current mitigation state"
        
        # Check for Event 1803 (OEM blocker) - if present, enforcement cannot proceed past Mitigation 1
        $has1803 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1803)
        if ($has1803) {
            Write-Log "WARNING" "Event 1803 detected - OEM has not provided PK-signed KEK. Enforcement limited."
        }
        
        # Detect which mitigations are already complete
        $has1037 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1037)
        $has1042 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1042)
        $has1808 = ($null -ne $CertStatus -and $CertStatus.EventId -eq 1808)
        
        # Boot manager check - Event 1799 indicates boot manager was installed
        $has1799 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1799)
                    
        # Check if 2011 CA is already revoked in DBX (Mitigation 3 complete without needing event)
        $pca2011Revoked = ($Ca2011RevokedInDbx.Count -gt 0)
        
        # Check if SVN is already in DBX (Mitigation 4 complete without needing event)
        $svnInDbx = ($null -ne $SvnStatus -and $null -ne $SvnStatus.DbxSVN)
        
        # -----------------------------------------------
        # Mitigation 1: Add Windows UEFI CA 2023 to DB (0x40)
        # -----------------------------------------------
        if ($Has2023InDb) {
            Write-Log "INFO" "Mitigation 1: SKIP - 2023 cert already in db"
            $results.Mitigation1 = 'AlreadyApplied'
            $results.ActionsSkipped += 'Mitigation 1 (DB cert)'
        }
        else {
            Write-Log "INFO" "Mitigation 1: Applying - adding Windows UEFI CA 2023 to DB (0x40)"
            try {
                $currentAv1 = (Get-ItemProperty -Path $regPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty AvailableUpdates -ErrorAction SilentlyContinue)
                if ($null -eq $currentAv1) { $currentAv1 = 0 }
                $mergedAv1 = $currentAv1 -bor 0x40
                $null = RegistryShouldBe -KeyPath $regPath -Name "AvailableUpdates" -Value $mergedAv1
                $null = Trigger-SecureBootTask
                Write-Log "SUCCESS" "Mitigation 1: Triggered DB cert update (0x$($mergedAv1.ToString('X4')))"
                $results.Mitigation1 = 'Applied'
                $results.ActionsApplied += 'Mitigation 1 (DB cert)'
                $results.RebootRequired = $true
                
                # Wait and verify
                Write-Log "INFO" "Mitigation 1: Waiting 30 seconds for update to process"
                Start-Sleep -Seconds 30
                
                # Re-read db to check if cert appeared
                $recheck = Get-UefiDatabaseCerts -Name db
                $recheckNames = @($recheck.Certs | Where-Object {
                    $_.Subject -match '2023'
                } | ForEach-Object {
                    if ($_.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() }
                })
                if ($recheckNames -contains 'Windows UEFI CA 2023') {
                    Write-Log "SUCCESS" "Mitigation 1: Verified - Windows UEFI CA 2023 now in db$(if ($recheckNames.Count -gt 1) { " (also found: $(($recheckNames | Where-Object { $_ -ne 'Windows UEFI CA 2023' }) -join ', '))" })"
                    $Has2023InDb = $true
                }
                elseif ($recheckNames.Count -gt 0) {
                    Write-Log "WARNING" "Mitigation 1: Found $($recheckNames -join ', ') in db but Windows UEFI CA 2023 not yet visible - may require reboot"
                }
                else {
                    Write-Log "WARNING" "Mitigation 1: Cert not yet visible in db - may require reboot"
                }
            }
            catch {
                Write-Log "ERROR" "Mitigation 1 failed: $($_.Exception.Message)"
                $results.Mitigation1 = 'Failed'
                return $results
            }
        }
        
        # -----------------------------------------------
        # Supplementary: Best-effort application of optional db certs
        # Microsoft UEFI CA 2023 (0x1000) + Option ROM UEFI CA 2023 (0x0800)
        # These are not required for enforcement progression but are preferred
        # for full compliance. Attempt only after Mitigation 1 confirms the
        # required Windows UEFI CA 2023 is in db. Does NOT gate Mitigation 2.
        # -----------------------------------------------
        if ($Has2023InDb) {
            # Always do a fresh db read - the caller's $DbCertsFound may have used raw byte
            # fallback (no -Decoded) which can miss certs that are actually present
            $suppFreshDb = Get-UefiDatabaseCerts -Name db
            $currentDbCerts = @($suppFreshDb.Certs | Where-Object {
                $_.Subject -match '2023'
            } | ForEach-Object {
                if ($_.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() }
            })
            if ($currentDbCerts.Count -gt $DbCertsFound.Count) {
                Write-Log "INFO" "Supplementary certs: Fresh db read found certs missed by initial scan: $($currentDbCerts -join ', ')"
            }
            
            # Also check events 1044/1045 - on devices without -Decoded, raw byte parsing
            # may miss certs that are actually in db. Events are the definitive signal.
            $has1044 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1044)
            $has1045 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1045)
            
            $optionalCerts = @(
                @{ Name = 'Microsoft UEFI CA 2023';            Bit = 0x1000; EventConfirmed = [bool]$has1045 }
                @{ Name = 'Microsoft Option ROM UEFI CA 2023'; Bit = 0x0800; EventConfirmed = [bool]$has1044 }
            )
            $missingOptional = @($optionalCerts | Where-Object { $currentDbCerts -notcontains $_.Name -and -not $_.EventConfirmed })
            
            if ($missingOptional.Count -gt 0) {
                $combinedBits = 0
                $missingOptional | ForEach-Object { $combinedBits = $combinedBits -bor $_.Bit }
                $missingNames = ($missingOptional | ForEach-Object { $_.Name }) -join ', '
                # OR with current AvailableUpdates to preserve existing bits (e.g. 0x100 boot manager)
                $currentAv = (Get-ItemProperty -Path $regPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                              Select-Object -ExpandProperty 'AvailableUpdates' -ErrorAction SilentlyContinue)
                if ($null -eq $currentAv) { $currentAv = 0 }
                $mergedBits = $currentAv -bor $combinedBits
                Write-Log "INFO" "Supplementary certs: Attempting best-effort install of $missingNames (0x$($combinedBits.ToString('X4')), merged with existing 0x$($currentAv.ToString('X4')) = 0x$($mergedBits.ToString('X4')))"
                try {
                    $null = RegistryShouldBe -KeyPath $regPath -Name "AvailableUpdates" -Value $mergedBits
                    $null = Trigger-SecureBootTask
                    Write-Log "SUCCESS" "Supplementary certs: Triggered update (0x$($mergedBits.ToString('X4')))"
                    $results.SupplementaryCertsAttempted = $true
                    
                    # Short wait and verify - don't block enforcement for long
                    Write-Log "INFO" "Supplementary certs: Waiting 15 seconds for processing"
                    Start-Sleep -Seconds 15
                    
                    # Re-read db to see if any appeared
                    $suppRecheck = Get-UefiDatabaseCerts -Name db
                    $suppRecheckNames = @($suppRecheck.Certs | Where-Object {
                        $_.Subject -match '2023'
                    } | ForEach-Object {
                        if ($_.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() }
                    })
                    $suppApplied = @($missingOptional | Where-Object { $suppRecheckNames -contains $_.Name })
                    $suppStillMissing = @($missingOptional | Where-Object { $suppRecheckNames -notcontains $_.Name })
                    
                    if ($suppApplied.Count -gt 0) {
                        Write-Log "SUCCESS" "Supplementary certs: Applied - $(($suppApplied | ForEach-Object { $_.Name }) -join ', ')"
                    }
                    if ($suppStillMissing.Count -gt 0) {
                        Write-Log "INFO" "Supplementary certs: Not yet visible - $(($suppStillMissing | ForEach-Object { $_.Name }) -join ', ') (may require reboot or firmware support)"
                    }
                }
                catch {
                    Write-Log "WARNING" "Supplementary certs: Best-effort install failed - $($_.Exception.Message) (non-blocking)"
                }
            }
            else {
                Write-Log "INFO" "Supplementary certs: All optional db certs already present"
            }
        }
        
        # -----------------------------------------------
        # Mitigation 2: Install 2023-signed boot manager (0x100)
        # -----------------------------------------------
        if ($has1799 -or $has1808) {
            Write-Log "INFO" "Mitigation 2: SKIP - 2023-signed boot manager already installed (Event $(if ($has1808) { '1808' } else { '1799' }))"
            $results.Mitigation2 = 'AlreadyApplied'
            $results.ActionsSkipped += 'Mitigation 2 (Boot manager)'
        }
        elseif (-not $Has2023InDb) {
            Write-Log "WARNING" "Mitigation 2: SKIP - Mitigation 1 must complete first (2023 cert not yet in db)"
            $results.Mitigation2 = 'Blocked'
            $results.Mitigation2BlockedReason = 'Awaiting DB cert (Mitigation 1)'
            $results.ActionsSkipped += 'Mitigation 2 (blocked by Mitigation 1)'
            return $results
        }
        else {
            Write-Log "INFO" "Mitigation 2: Applying - installing 2023-signed boot manager (0x100)"
            try {
                # OR with current AvailableUpdates to preserve existing bits
                $currentAv2 = (Get-ItemProperty -Path $regPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                               Select-Object -ExpandProperty 'AvailableUpdates' -ErrorAction SilentlyContinue)
                if ($null -eq $currentAv2) { $currentAv2 = 0 }
                $mergedAv2 = $currentAv2 -bor 0x100
                $null = RegistryShouldBe -KeyPath $regPath -Name "AvailableUpdates" -Value $mergedAv2
                $null = Trigger-SecureBootTask
                Write-Log "SUCCESS" "Mitigation 2: Triggered boot manager update (0x$($mergedAv2.ToString('X4')))"
                $results.Mitigation2 = 'Applied'
                $results.ActionsApplied += 'Mitigation 2 (Boot manager)'
                $results.RebootRequired = $true
                
                Write-Log "INFO" "Mitigation 2: Waiting 30 seconds for update to process"
                Start-Sleep -Seconds 30
                
                # Check for 1799 event
                $postCheck = Check-PostTriggerEvents -Minutes 2
                if ($postCheck -eq 'Pending1808' -or $postCheck -eq 'Compliant') {
                    Write-Log "SUCCESS" "Mitigation 2: Boot manager installed (post-trigger: $postCheck)"
                    # Update event flags so the Mitigation 3+4 gate knows boot manager is confirmed
                    if ($postCheck -eq 'Compliant') { $has1808 = $true } else { $has1799 = $true }
                }
                else {
                    Write-Log "INFO" "Mitigation 2: Boot manager update processing - may need reboot"
                    # Boot manager was NOT confirmed installed (no 1799/1808).
                    # Re-query events: if 1800 fired during the wait, a reboot is required
                    # before Stage 3+4 can proceed. Mark Mitigation 2 as needing verification.
                    $mit2PostStatus = Get-CertUpdateEventStatus
                    if ($null -ne $mit2PostStatus -and $mit2PostStatus.EventId -eq 1800) {
                        Write-Log "WARNING" "Mitigation 2: Event 1800 detected - reboot required before boot manager can complete"
                        $mit2NeedsReboot = $true
                    }
                    else {
                        # No 1799/1808/1800 - boot manager update status unknown, don't assume success
                        Write-Log "WARNING" "Mitigation 2: No confirmation event (1799/1800/1808) - cannot verify boot manager install"
                        $mit2NeedsReboot = $true
                    }
                }
            }
            catch {
                Write-Log "ERROR" "Mitigation 2 failed: $($_.Exception.Message)"
                $results.Mitigation2 = 'Failed'
                return $results
            }
        }
        
        # -----------------------------------------------
        # Mitigation 3 + 4: Revoke PCA 2011 + Apply SVN (0x280)
        # Per CVE-2023-24932 enterprise guidance, these can be applied together in one step.
        # Uses Test-SvnStagePrerequisites for the Stage 1+2 gate check.
        # -----------------------------------------------
        $mit3Done = $pca2011Revoked -or $has1037
        $mit4Done = $svnInDbx -or $has1042
        $bothDone = $mit3Done -and $mit4Done
        
        # Run the shared prerequisite check (ground truth + manifest + events)
        $prereqs = Test-SvnStagePrerequisites -Has2023InDb $Has2023InDb -CertStatus $CertStatus -SvnEnforcementResult $results
        Write-Log "INFO" "Mitigation 3+4 gate: Stage1=$($prereqs.Stage1Done) ($($prereqs.Stage1Detail)), Stage2=$($prereqs.Stage2Done) ($($prereqs.Stage2Detail)), Reboot=$($prereqs.RebootPending), AllMet=$($prereqs.AllPrereqsMet)"
        
        if ($bothDone) {
            Write-Log "INFO" "Mitigation 3+4: SKIP - 2011 CA already revoked in DBX and SVN already applied"
            $results.Mitigation3 = 'AlreadyApplied'
            $results.Mitigation4 = 'AlreadyApplied'
            $results.ActionsSkipped += 'Mitigation 3 (2011 revocation)'
            $results.ActionsSkipped += 'Mitigation 4 (SVN update)'
        }
        elseif (-not $prereqs.AllPrereqsMet) {
            Write-Log "WARNING" "Mitigation 3+4: BLOCKED - $($prereqs.BlockReason)"
            if (-not $mit3Done) {
                $results.Mitigation3 = 'Blocked'
                $results.Mitigation3BlockedReason = $prereqs.BlockReason
                $results.ActionsSkipped += 'Mitigation 3 (blocked - prerequisites incomplete)'
            }
            else {
                $results.Mitigation3 = 'AlreadyApplied'
                $results.ActionsSkipped += 'Mitigation 3 (2011 revocation)'
            }
            if (-not $mit4Done) {
                $results.Mitigation4 = 'Blocked'
                $results.Mitigation4BlockedReason = $prereqs.BlockReason
                $results.ActionsSkipped += 'Mitigation 4 (blocked - prerequisites incomplete)'
            }
            else {
                $results.Mitigation4 = 'AlreadyApplied'
                $results.ActionsSkipped += 'Mitigation 4 (SVN update)'
            }
        }
        elseif ((-not $mit3Done -and $prereqs.Stage3BitPending) -or (-not $mit4Done -and $prereqs.Stage4BitPending)) {
            # Bits already in manifest, just waiting for reboot - don't re-trigger
            $pendingParts = @()
            $pendingStages = @()
            if (-not $mit3Done -and $prereqs.Stage3BitPending) {
                $pendingParts += 'Mitigation 3 (0x80)'
                $pendingStages += 'Stage 3'
            }
            if (-not $mit4Done -and $prereqs.Stage4BitPending) {
                $pendingParts += 'Mitigation 4 (0x200)'
                $pendingStages += 'Stage 4'
            }
            Write-Log "INFO" "SVN enforcement: Already pending in manifest ($($pendingParts -join ', ')) - reboot required to finalize"
            if ($results.BitLockerSuspension.Status -eq 'NotRequired') {
                $results.BitLockerSuspension = Suspend-SystemBitLockerVolumesForSvn `
                    -Enabled $SuspendBitlockerForSVN `
                    -RebootCount 2 `
                    -Stages $pendingStages
            }
            $results.BitLockerSuspension.PendingManifest = $true
            
            $bitLockerReady = $results.BitLockerSuspension.CanProceed
            $bitLockerBlockReason = 'BitLocker suspension failed; do not reboot until the failed volumes are protected or manually suspended'
            if (-not $bitLockerReady) {
                Write-Log "ERROR" "Stage 3/4 bits are already pending, but BitLocker safety preparation failed. Do not reboot this device until resolved."
            }
            
            if (-not $mit3Done -and $prereqs.Stage3BitPending) {
                if ($bitLockerReady) {
                    $results.Mitigation3 = 'PendingReboot'
                    $results.ActionsSkipped += 'Mitigation 3 (pending reboot)'
                }
                else {
                    $results.Mitigation3 = 'Blocked'
                    $results.Mitigation3BlockedReason = $bitLockerBlockReason
                    $results.ActionsSkipped += 'Mitigation 3 (pending manifest; BitLocker suspension failed)'
                }
            }
            elseif ($mit3Done) {
                $results.Mitigation3 = 'AlreadyApplied'
                $results.ActionsSkipped += 'Mitigation 3 (2011 revocation)'
            }
            if (-not $mit4Done -and $prereqs.Stage4BitPending) {
                if ($bitLockerReady) {
                    $results.Mitigation4 = 'PendingReboot'
                    $results.ActionsSkipped += 'Mitigation 4 (pending reboot)'
                }
                else {
                    $results.Mitigation4 = 'Blocked'
                    $results.Mitigation4BlockedReason = $bitLockerBlockReason
                    $results.ActionsSkipped += 'Mitigation 4 (pending manifest; BitLocker suspension failed)'
                }
            }
            elseif ($mit4Done) {
                $results.Mitigation4 = 'AlreadyApplied'
                $results.ActionsSkipped += 'Mitigation 4 (SVN update)'
            }
            $results.RebootRequired = $true
        }
        else {
            # Determine what to apply
            if (-not $mit3Done -and -not $mit4Done) {
                # Apply both together (0x280) per CVE-2023-24932 enterprise guidance
                $triggerValue = 0x280
                $desc = "Mitigation 3+4 combined (revoke 2011 CA + apply SVN) (0x280)"
                $targetStages = @('Stage 3','Stage 4')
            }
            elseif (-not $mit3Done) {
                $triggerValue = 0x80
                $desc = "Mitigation 3 only (revoke 2011 CA in DBX) (0x80)"
                $targetStages = @('Stage 3')
            }
            else {
                $triggerValue = 0x200
                $desc = "Mitigation 4 only (apply SVN to DBX) (0x200)"
                $targetStages = @('Stage 4')
            }
            
            # Suspend immediately before the irreversible registry/task trigger. This
            # covers combined Stage 3+4 as well as either stage applied by itself.
            $results.BitLockerSuspension = Suspend-SystemBitLockerVolumesForSvn `
                -Enabled $SuspendBitlockerForSVN `
                -RebootCount 2 `
                -Stages $targetStages
            
            if (-not $results.BitLockerSuspension.CanProceed) {
                $bitLockerBlockReason = 'BitLocker suspension failed; Stage 3/4 trigger was not written'
                Write-Log "ERROR" "$desc blocked: $bitLockerBlockReason"
                if (-not $mit3Done) {
                    $results.Mitigation3 = 'Blocked'
                    $results.Mitigation3BlockedReason = $bitLockerBlockReason
                    $results.ActionsSkipped += 'Mitigation 3 (BitLocker suspension failed)'
                }
                else {
                    $results.Mitigation3 = 'AlreadyApplied'
                }
                if (-not $mit4Done) {
                    $results.Mitigation4 = 'Blocked'
                    $results.Mitigation4BlockedReason = $bitLockerBlockReason
                    $results.ActionsSkipped += 'Mitigation 4 (BitLocker suspension failed)'
                }
                else {
                    $results.Mitigation4 = 'AlreadyApplied'
                }
            }
            else {
                Write-Log "INFO" "$desc"
                try {
                    # OR with current AvailableUpdates to preserve existing bits
                    $currentAv34 = (Get-ItemProperty -Path $regPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                                    Select-Object -ExpandProperty 'AvailableUpdates' -ErrorAction SilentlyContinue)
                    if ($null -eq $currentAv34) { $currentAv34 = 0 }
                    $mergedValue = $currentAv34 -bor $triggerValue
                    if ($mergedValue -ne $triggerValue) {
                        Write-Log "INFO" "Mitigation 3+4: OR with existing 0x$($currentAv34.ToString('X4')) = 0x$($mergedValue.ToString('X4'))"
                    }
                    $null = RegistryShouldBe -KeyPath $regPath -Name "AvailableUpdates" -Value $mergedValue
                    $null = Trigger-SecureBootTask
                    Write-Log "SUCCESS" "Triggered $desc"
                    if (-not $mit3Done) {
                        $results.Mitigation3 = 'Applied'
                        $results.ActionsApplied += 'Mitigation 3 (2011 revocation)'
                    }
                    else {
                        $results.Mitigation3 = 'AlreadyApplied'
                    }
                    if (-not $mit4Done) {
                        $results.Mitigation4 = 'Applied'
                        $results.ActionsApplied += 'Mitigation 4 (SVN update)'
                    }
                    else {
                        $results.Mitigation4 = 'AlreadyApplied'
                    }
                    $results.RebootRequired = $true
                    
                    Write-Log "INFO" "Waiting 30 seconds for update to process"
                    Start-Sleep -Seconds 30
                    
                    # Verify via event log
                    $postCheck1037 = @(Get-WinEvent -FilterHashtable @{
                        LogName = 'System'; ProviderName = 'Microsoft-Windows-TPM-WMI'; Id = 1037
                        StartTime = (Get-Date).AddMinutes(-2)
                    } -ErrorAction SilentlyContinue)
                    $postCheck1042 = @(Get-WinEvent -FilterHashtable @{
                        LogName = 'System'; ProviderName = 'Microsoft-Windows-TPM-WMI'; Id = 1042
                        StartTime = (Get-Date).AddMinutes(-2)
                    } -ErrorAction SilentlyContinue)
                    if ($postCheck1037.Count -gt 0) {
                        Write-Log "SUCCESS" "Event 1037 confirmed - 2011 CA revoked in DBX"
                    }
                    if ($postCheck1042.Count -gt 0) {
                        Write-Log "SUCCESS" "Event 1042 confirmed - SVN applied to DBX"
                    }
                    if ($postCheck1037.Count -eq 0 -and $postCheck1042.Count -eq 0) {
                        Write-Log "INFO" "Events 1037/1042 not yet observed - reboot required to complete"
                    }
                }
                catch {
                    Write-Log "ERROR" "Mitigation 3+4 failed: $($_.Exception.Message)"
                    if (-not $mit3Done) { $results.Mitigation3 = 'Failed' }
                    if (-not $mit4Done) { $results.Mitigation4 = 'Failed' }
                }
            }
        }
        
        # Summary
        if ($results.ActionsApplied.Count -gt 0) {
            Write-Log "INFO" "SVN Enforcement applied: $($results.ActionsApplied -join ', ')"
        }
        if ($results.ActionsSkipped.Count -gt 0) {
            Write-Log "INFO" "SVN Enforcement skipped: $($results.ActionsSkipped -join ', ')"
        }
        if ($results.RebootRequired) {
            if ($results.BitLockerSuspension.Status -eq 'Failed' -and $results.BitLockerSuspension.PendingManifest) {
                Write-Log "ERROR" "Stage 3/4 is pending, but this device MUST NOT REBOOT until the BitLocker suspension failures are resolved"
            }
            else {
                Write-Log "WARNING" "A reboot is required to complete the applied mitigations"
            }
        }
        
        return $results
    }
}

# =========================================
# PROCESS Block: Data Gathering & Logic
#   Steps 1-2.6: Secure Boot status, cert parsing, dbx cross-check,
#   event log, servicing registry, SVN compliance, SVN enforcement,
#   opt-in check, trigger logic
# =========================================
process {
    Write-Host "`n=== Secure Boot Certificate Status Check ==="
    
    # -----------------------------------------------
    # Step 1: Determine Secure Boot state
    # -----------------------------------------------
    Write-Log "INFO" "Checking Secure Boot UEFI status"
    $secureBoot = Get-SecureBootStatus
    Write-Log "INFO" "Secure Boot status: $secureBoot"
    
    # -----------------------------------------------
    # Step 1.5: If Enabled, parse db, KEK, and dbx certificates
    # -----------------------------------------------
    # The full set of 2023 certificates Microsoft is rotating to:
    #   db certs:  Windows UEFI CA 2023, Microsoft UEFI CA 2023, Microsoft Option ROM UEFI CA 2023
    #   KEK cert:  Microsoft Corporation KEK 2K CA 2023
    # KEK (Key Exchange Key) is the trust authority that authorizes writes to db.
    # When Windows Update pushes a signed update payload to write new certs into db,
    # the firmware verifies the payload signature against the KEK database.
    # If the 2023 KEK authority cert is missing, the firmware will reject the write
    # even if the UEFI attributes indicate db is runtime-writable.
    $updatedDbCertNames  = @(
        'Windows UEFI CA 2023',
        'Microsoft UEFI CA 2023',
        'Microsoft Option ROM UEFI CA 2023'
    )
    $updatedKekCertName  = 'Microsoft Corporation KEK 2K CA 2023'
    
    $has2023InDb        = $false
    $allDbCertsPresent  = $false
    $has2023InDbDefault = $false
    $has2023InKek       = $false
    $dbCertsFound       = @()   # Which 2023 db certs are present
    $scheduledTaskPresent = $false
    $dbIsOsWritable     = $false
    $pkCerts            = @()
    $pkSubject          = $null
    $pkIsTrusted        = $true
    $hypervisor         = $null    # 'VMware' | 'VirtualBox' | $null
    $defaultsPresent    = @{ PKDefault = $false; KEKDefault = $false; dbDefault = $false; dbxDefault = $false }
    
    if ($secureBoot -eq 'Enabled') {
        # --- Parse PK (Platform Key - root of Secure Boot trust) ---
        # PK authorizes updates to KEK. Typically a vendor/OEM cert on physical hardware,
        # or an empty-signature VMware/VirtualBox marker on hypervisors.
        Write-Log "INFO" "Parsing PK certificate$(if ($script:HasDecodedParam) { ' (using -Decoded)' })"
        $pkResult = Get-UefiDatabaseCerts -Name PK
        $pkCerts  = $pkResult.Certs
        if ($pkCerts.Count -eq 0) {
            Write-Log "INFO" "No certificates found in PK (device may be in setup mode)"
        }
        else {
            foreach ($cert in $pkCerts) {
                $shortSubject = (($cert.Subject -split ',') | Select-Object -First 2 | ForEach-Object { $_.Trim() }) -join ', '
                Write-Log "INFO" "PK Cert: $shortSubject"
                if ($null -eq $pkSubject) { $pkSubject = $cert.Subject }
                # Hypervisor detection (Part 2F)
                if ($cert.PSObject.Properties['Hypervisor'] -and $null -ne $cert.Hypervisor) {
                    $hypervisor = $cert.Hypervisor
                }
                elseif ($cert.Subject -match '(?i)VirtualBox') {
                    $hypervisor = 'VirtualBox'
                }
                # Trust check: placeholder/example PKs are untrusted
                if ($cert.Subject -match '(?i)(DO NOT|Example)') {
                    $pkIsTrusted = $false
                }
            }
            if ($null -ne $hypervisor) {
                Write-Log "INFO" "Hypervisor-managed Secure Boot detected: $hypervisor"
            }
            if (-not $pkIsTrusted) {
                if ($pkSubject -match '(?i)(AMI|DO NOT)') {
                    Write-Log "ERROR" "PK is the publicly-leaked AMI Test PK (PKFail / CVE-2024-8105) - Secure Boot chain of trust is broken. BIOS update required."
                }
                else {
                    Write-Log "WARNING" "PK is a placeholder/example certificate (untrusted) - Secure Boot chain is effectively open"
                }
            }
        }
        
        # --- Parse db (allowed signatures) ---
        Write-Log "INFO" "Parsing db certificates$(if ($script:HasDecodedParam) { ' (using -Decoded)' })"
        $dbResult = Get-UefiDatabaseCerts -Name db
        $dbCerts  = $dbResult.Certs
        $dbBytes  = $dbResult.Bytes
        if ($dbCerts.Count -eq 0) {
            Write-Log "INFO" "No X509 certificates found in db"
        }
        else {
            foreach ($cert in $dbCerts) {
                $shortSubject = (($cert.Subject -split ',') | Select-Object -First 2 | ForEach-Object { $_.Trim() }) -join ', '
                $validFrom = $cert.NotBefore.ToString('MM/dd/yyyy')
                $validTo = $cert.NotAfter.ToString('MM/dd/yyyy')
                Write-Log "INFO" "db Cert: $shortSubject, ValidFrom=$validFrom, ValidTo=$validTo"
            }
        }
        
        # --- Parse KEK (key exchange keys - authorizes writes to db) ---
        Write-Log "INFO" "Parsing KEK certificates$(if ($script:HasDecodedParam) { ' (using -Decoded)' })"
        $kekResult = Get-UefiDatabaseCerts -Name KEK
        $kekCerts  = $kekResult.Certs
        if ($kekCerts.Count -eq 0) {
            Write-Log "INFO" "No X509 certificates found in KEK"
        }
        else {
            foreach ($cert in $kekCerts) {
                $shortSubject = (($cert.Subject -split ',') | Select-Object -First 2 | ForEach-Object { $_.Trim() }) -join ', '
                $validFrom = $cert.NotBefore.ToString('MM/dd/yyyy')
                $validTo = $cert.NotAfter.ToString('MM/dd/yyyy')
                Write-Log "INFO" "KEK Cert: $shortSubject, ValidFrom=$validFrom, ValidTo=$validTo"
            }
        }
        
        # --- Parse dbx (revocation list) ---
        Write-Log "INFO" "Parsing dbx certificates$(if ($script:HasDecodedParam) { ' (using -Decoded)' })"
        $dbxResult = Get-UefiDatabaseCerts -Name dbx
        $dbxCerts  = $dbxResult.Certs
        $dbxBytes  = $dbxResult.Bytes
        if ($dbxCerts.Count -eq 0) {
            Write-Log "INFO" "No X509 certificates found in dbx"
        }
        else {
            foreach ($cert in $dbxCerts) {
                if ([string]::IsNullOrWhiteSpace($cert.Subject)) { continue }
                $shortSubject = (($cert.Subject -split ',') | Select-Object -First 2 | ForEach-Object { $_.Trim() }) -join ', '
                $validFrom = $cert.NotBefore.ToString('MM/dd/yyyy')
                $validTo = $cert.NotAfter.ToString('MM/dd/yyyy')
                Write-Log "INFO" "dbx Cert: $shortSubject, ValidFrom=$validFrom, ValidTo=$validTo"
            }
        }
        
        # --- Cross-check: are any 2011 CAs revoked in DBX? (Stage 3 indicator) ---
        $ca2011RevokedInDbx = @()   # Which 2011 CAs appear in the revocation list
        $oldCAs = @(
            'Microsoft Corporation UEFI CA 2011'
            'Microsoft Windows Production PCA 2011'
        )
        try {
            if ($dbxCerts.Count -gt 0) {
                # Check parsed cert objects by subject CN
                foreach ($oldCA in $oldCAs) {
                    foreach ($cert in $dbxCerts) {
                        if ($cert.Subject -match [regex]::Escape($oldCA)) {
                            $ca2011RevokedInDbx += $oldCA
                            break
                        }
                    }
                }
            }
            elseif ($null -ne $dbxBytes) {
                # Fallback: raw byte string match
                $dbxRawText = [System.Text.Encoding]::ASCII.GetString($dbxBytes)
                foreach ($oldCA in $oldCAs) {
                    if ($dbxRawText -match [regex]::Escape($oldCA)) {
                        $ca2011RevokedInDbx += $oldCA
                    }
                }
            }
            if ($ca2011RevokedInDbx.Count -gt 0) {
                Write-Log "INFO" "2011 CA revoked in dbx: $($ca2011RevokedInDbx -join ', ')"
            }
            else {
                Write-Log "INFO" "No 2011 CAs found in dbx (not yet revoked)"
            }
        }
        catch {
            Write-Log "WARNING" "Failed to cross-check 2011 CAs in dbx: $($_.Exception.Message)"
        }
        
        # --- Check for 2023 certs in db (check all 3 db-level certs) ---
        try {
            if ($dbCerts.Count -gt 0) {
                # Prefer cert object matching
                foreach ($certName in $updatedDbCertNames) {
                    foreach ($cert in $dbCerts) {
                        if ($cert.Subject -match [regex]::Escape($certName)) {
                            $dbCertsFound += $certName
                            break
                        }
                    }
                }
            }
            elseif ($null -ne $dbBytes) {
                # Fallback: raw byte string match
                $dbRawText = [System.Text.Encoding]::ASCII.GetString($dbBytes)
                foreach ($certName in $updatedDbCertNames) {
                    if ($dbRawText -match [regex]::Escape($certName)) {
                        $dbCertsFound += $certName
                    }
                }
            }
            $has2023InDb = $dbCertsFound -contains 'Windows UEFI CA 2023'
            $allDbCertsPresent = ($dbCertsFound.Count -eq $updatedDbCertNames.Count)
            if ($has2023InDb) {
                if ($allDbCertsPresent) {
                    Write-Log "INFO" "All 2023 certs found in db: $($dbCertsFound -join ', ')"
                }
                else {
                    $missingDb = $updatedDbCertNames | Where-Object { $dbCertsFound -notcontains $_ }
                    Write-Log "WARNING" "2023 certs found in db: $($dbCertsFound -join ', ') | Missing: $($missingDb -join ', ')"
                }
            }
            else {
                Write-Log "INFO" "No 2023 certs found in db"
            }
        }
        catch {
            Write-Log "WARNING" "Failed to check 2023 certs in db: $($_.Exception.Message)"
        }
        
        # --- Check for 2023 KEK authority cert ---
        try {
            $has2023InKek = $false
            if ($kekCerts.Count -gt 0) {
                foreach ($cert in $kekCerts) {
                    if ($cert.Subject -match [regex]::Escape($updatedKekCertName)) {
                        $has2023InKek = $true
                        break
                    }
                }
            }
            Write-Log "INFO" "2023 KEK authority cert ($updatedKekCertName): $(if ($has2023InKek) { 'Present' } else { 'Missing' })"
        }
        catch {
            Write-Log "WARNING" "Failed to check 2023 cert in KEK: $($_.Exception.Message)"
        }
        
        # --- If not in db, check dbDefault ---
        $dbDefaultCertsFound = @()   # Which 2023 certs are present in dbDefault
        if (-not $has2023InDb) {
            try {
                $dbDefaultResult = Get-UefiDatabaseCerts -Name dbDefault
                $dbDefaultCerts = $dbDefaultResult.Certs
                $dbDefaultBytes = $dbDefaultResult.Bytes
                if ($dbDefaultCerts.Count -gt 0) {
                    foreach ($certName in $updatedDbCertNames) {
                        foreach ($cert in $dbDefaultCerts) {
                            if ($cert.Subject -match [regex]::Escape($certName)) {
                                $dbDefaultCertsFound += $certName
                                break
                            }
                        }
                    }
                }
                elseif ($null -ne $dbDefaultBytes) {
                    $dbDefaultRawText = [System.Text.Encoding]::ASCII.GetString($dbDefaultBytes)
                    foreach ($certName in $updatedDbCertNames) {
                        if ($dbDefaultRawText -match [regex]::Escape($certName)) {
                            $dbDefaultCertsFound += $certName
                        }
                    }
                }
                $has2023InDbDefault = $dbDefaultCertsFound.Count -gt 0
                if ($has2023InDbDefault) {
                    Write-Log "INFO" "2023 certs found in dbDefault: $($dbDefaultCertsFound -join ', ')"
                }
                else {
                    Write-Log "INFO" "No 2023 certs found in dbDefault"
                }
            }
            catch {
                Write-Log "WARNING" "Failed to check 2023 cert in dbDefault: $($_.Exception.Message)"
            }
        }
        
        # --- Parse factory default databases (PKDefault / KEKDefault / dbDefault / dbxDefault) ---
        # Presence of all four is required for the BIOS "Reset Secure Boot keys" recovery option
        # to work. Devices missing all four cannot recover from a broken cert chain without an
        # OEM firmware update.
        foreach ($defName in @('PKDefault','KEKDefault','dbDefault','dbxDefault')) {
            try {
                $res = Get-UefiDatabaseCerts -Name $defName
                if ($res.Certs.Count -gt 0 -or ($null -ne $res.Bytes -and $res.Bytes.Length -gt 0)) {
                    $defaultsPresent[$defName] = $true
                    Write-Log "INFO" "$defName is present ($($res.Certs.Count) cert(s))"
                }
                else {
                    Write-Log "WARNING" "$defName is MISSING - BIOS 'Reset Secure Boot keys' recovery will not restore this variable"
                }
            }
            catch {
                Write-Log "WARNING" "Failed to read ${defName}: $($_.Exception.Message)"
            }
        }
        $defaultsAllMissing  = -not ($defaultsPresent.PKDefault -or $defaultsPresent.KEKDefault -or $defaultsPresent.dbDefault -or $defaultsPresent.dbxDefault)
        $defaultsSomeMissing = -not ($defaultsPresent.PKDefault -and $defaultsPresent.KEKDefault -and $defaultsPresent.dbDefault -and $defaultsPresent.dbxDefault)
        if ($defaultsAllMissing) {
            Write-Log "WARNING" "All UEFI default databases are missing - 'Reset Secure Boot keys' BIOS option will not function"
        }
        elseif ($defaultsSomeMissing) {
            $missingDefaults = $defaultsPresent.Keys | Where-Object { -not $defaultsPresent[$_] }
            Write-Log "INFO" "Some UEFI default databases are missing: $($missingDefaults -join ', ')"
        }
        
        # --- Check Secure-Boot-Update scheduled task existence ---
        Write-Host "`n === Secure Boot Update Task Check ==="
        if (Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\*" -TaskName "Secure-Boot-Update" -ErrorAction SilentlyContinue) {
            $scheduledTaskPresent = $true
            Write-Log "INFO" "Scheduled task '\Microsoft\Windows\PI\Secure-Boot-Update' is present"
        }
        else {
            Write-Log "WARNING" "Scheduled task '\Microsoft\Windows\PI\Secure-Boot-Update' is MISSING. Windows Update may not be able to apply Secure Boot certificate updates."
        }
        
        # --- Passive UEFI variable attributes check for 'db' ---
        Write-Host "`n === Windows UEFI DB Access Check ==="
        Write-Log "INFO" "Reading passive UEFI variable attributes for 'db' from the inbox Get-SecureBootUEFI result"
        $dbAttributes     = $dbResult.Attributes
        $hasRuntimeAccess = Test-UefiVariableAttribute -Attributes $dbAttributes -Mask 0x00000004 -DisplayName 'RUNTIME ACCESS'
        $hasTimeBasedAuth = Test-UefiVariableAttribute -Attributes $dbAttributes -Mask 0x00000020 -DisplayName 'TIME BASED AUTHENTICATED WRITE ACCESS'
        $uefiAllowsWrite  = $null -ne $dbAttributes -and $hasRuntimeAccess -and $hasTimeBasedAuth
        $dbAttributeDisplay = if ($null -eq $dbAttributes) { 'Unavailable' } else { (@($dbAttributes) -join ', ') }
        Write-Log "INFO" "db attributes:`n$dbAttributeDisplay"
        Write-Log "INFO" "Runtime Access: $hasRuntimeAccess (OS can access UEFI var at runtime)"
        Write-Log "INFO" "Time-Based Authenticated Write: $hasTimeBasedAuth (Windows can sign and push updates)"
        
        # db is truly OS-writable only if UEFI attributes allow it AND the 2023 KEK authority is present
        # (KEK authorizes the signed payload Windows Update uses to write to db)
        if ($uefiAllowsWrite -and $has2023InKek) {
            $dbIsOsWritable = $true
            Write-Log "INFO" "OS capable of writing to UEFI db: True (UEFI attributes + KEK authority both present)"
        }
        elseif ($uefiAllowsWrite -and -not $has2023InKek) {
            $dbIsOsWritable = $false
            Write-Log "WARNING" "UEFI attributes allow runtime writes, but 2023 KEK authority cert is missing. Windows Update cannot sign the payload - db is NOT effectively OS-writable."
        }
        else {
            $dbIsOsWritable = $false
            Write-Log "INFO" "OS capable of writing to UEFI db: False"
        }
        Write-Host ""
    }
    
    # -----------------------------------------------
    # Step 2: Query event log (only when Secure Boot is Enabled)
    # -----------------------------------------------
    $certStatus = $null
    if ($secureBoot -eq 'Enabled') {
        Write-Log "INFO" "Secure Boot is enabled; querying event log for certificate update events"
        $certStatus = Get-CertUpdateEventStatus
        
        # Clarify when the event status contradicts actual cert state
        if ($certStatus.Status -eq 'ActionRequired' -and $has2023InDb) {
            Write-Log "INFO" "Certificate event status: Stale 1801 - 2023 cert is already in db; OS has not yet acknowledged via 1808"
        }
        else {
            Write-Log "INFO" "Certificate event status: $($certStatus.Status) - $($certStatus.EventMessage)"
        }
    }
    else {
        Write-Log "INFO" "Skipping event log check (Secure Boot is $secureBoot)"
    }
    
    # --- Augment dbCertsFound with event 1044/1045 for devices where raw byte parsing missed variable certs ---
    if ($null -ne $certStatus -and -not $allDbCertsPresent) {
        $eventAugmented = $false
        if ($dbCertsFound -notcontains 'Microsoft UEFI CA 2023' -and (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1045)) {
            $dbCertsFound += 'Microsoft UEFI CA 2023'
            $eventAugmented = $true
            Write-Log "INFO" "Event 1045 confirms Microsoft UEFI CA 2023 is in db (not visible via raw parse)"
        }
        if ($dbCertsFound -notcontains 'Microsoft Option ROM UEFI CA 2023' -and (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1044)) {
            $dbCertsFound += 'Microsoft Option ROM UEFI CA 2023'
            $eventAugmented = $true
            Write-Log "INFO" "Event 1044 confirms Microsoft Option ROM UEFI CA 2023 is in db (not visible via raw parse)"
        }
        if ($eventAugmented) {
            $allDbCertsPresent = ($dbCertsFound.Count -eq $updatedDbCertNames.Count)
            Write-Log "INFO" "Updated db cert inventory via events: $($dbCertsFound -join ', ')$(if ($allDbCertsPresent) { ' (all present)' })"
        }
    }
    
    # -----------------------------------------------
    # Step 2.1: Read Secure Boot servicing registry (only when Secure Boot is Enabled)
    # -----------------------------------------------
    $servicingStatus = $null
    if ($secureBoot -eq 'Enabled') {
        Write-Host "`n === Secure Boot Servicing Registry ==="
        $servicingStatus = Get-SecureBootServicingStatus
        
        if ($null -ne $servicingStatus.UEFICA2023Status) {
            Write-Log "INFO" "UEFICA2023Status: $($servicingStatus.UEFICA2023Status)"
        }
        else {
            Write-Log "INFO" "UEFICA2023Status: Not set"
        }
        
        if ($null -ne $servicingStatus.WindowsUEFICA2023Capable) {
            $capableDesc = switch ($servicingStatus.WindowsUEFICA2023Capable) {
                1 { 'Cert in DB' }
                2 { 'Cert in DB + booting from 2023 boot manager' }
                default { 'Cert not in DB' }
            }
            Write-Log "INFO" "WindowsUEFICA2023Capable: $($servicingStatus.WindowsUEFICA2023Capable) ($capableDesc)"
        }
        
        if ($null -ne $servicingStatus.UEFICA2023Error -and $servicingStatus.UEFICA2023Error -ne 0) {
            Write-Log "WARNING" "UEFICA2023Error: $($servicingStatus.UEFICA2023ErrorHex) - $($servicingStatus.UEFICA2023ErrorMessage)"
        }
        
        if ($null -ne $servicingStatus.UEFICA2023ErrorEvent) {
            Write-Log "INFO" "UEFICA2023ErrorEvent: $($servicingStatus.UEFICA2023ErrorEvent) - $($servicingStatus.UEFICA2023ErrorEventDesc)"
        }
        
        if ($null -ne $servicingStatus.CanAttemptUpdateAfter) {
            $updateAfterStr = $servicingStatus.CanAttemptUpdateAfter.ToString('yyyy-MM-dd HH:mm')
            if ($servicingStatus.CanAttemptUpdateAfter -gt (Get-Date)) {
                Write-Log "WARNING" "CanAttemptUpdateAfter: $updateAfterStr (update delayed until this time)"
            }
            else {
                Write-Log "INFO" "CanAttemptUpdateAfter: $updateAfterStr (past - update can proceed)"
            }
        }
        
        # Use UEFICA2023Status as supplemental compliance signal
        if ($servicingStatus.UEFICA2023Status -eq 'Updated' -and $certStatus -and $certStatus.Status -ne 'Compliant') {
            Write-Log "INFO" "Servicing registry reports 'Updated' but event log status is '$($certStatus.Status)' - servicing confirms compliance"
        }
        
        # Log device attributes if available
        if ($null -ne $servicingStatus.OEMManufacturerName) {
            Write-Log "INFO" "OEM: $($servicingStatus.OEMManufacturerName) | Model: $($servicingStatus.OEMModelNumber) | FW: $($servicingStatus.FirmwareVersion)"
        }
        
        Write-Host ""
    }
    
    # -----------------------------------------------
    # Step 2.15: SVN Compliance check
    # SVN (Security Version Number) tracks boot component revocation levels in UEFI DBX.
    # Part of the Secure Boot hardening rollout (KB5046714 -> KB5077241):
    #   Stage 1 (May 2024)   : 2023 certs added to db via Windows Update
    #   Stage 2 (Feb 2025)   : 2023 boot manager deployed, Get-SecureBootSVN cmdlet added (KB5077241)
    #   Stage 3 (June 2026)  : PCA 2011 revoked in dbx, SVN enforcement begins
    #   Stage 4 (est. 2027)  : Full enforcement - 2011 certs removed from db
    # SVN progression: 0.0 (none) -> 2.0 (PCA 2011 revoked via DBXUpdate2024.bin) -> 7.0 (via DBXUpdateSVN.bin)
    # Uses Get-SecureBootSVN cmdlet (KB5077241+) when available; always parses raw DBX bytes
    # for pending update detection (compares live DBX against DBXUpdateSVN.bin staging file).
    # Source: https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates
    # Source: https://github.com/microsoft/secureboot_objects
    # -----------------------------------------------
    $svnStatus = $null
    if ($secureBoot -eq 'Enabled') {
        Write-Host " === Secure Boot SVN Compliance ==="
        # Always attempt SVN, raw DBX provides pending update detection, cmdlet adds richer info
        $svnStatus = Get-SecureBootSVNStatus -DbxBytes $dbxBytes
        if ($null -ne $svnStatus) {
            # Cross-reference: if not compliant but 2011 CA not yet revoked, it's expected (pre-Stage 3)
            $svnStatus.RevocationPending = (-not $svnStatus.IsCompliant -and $ca2011RevokedInDbx.Count -eq 0)
            # Cross-reference events 1037 (2011 CA revoked in DBX) and 1042 (SVN applied to DBX) for stage confirmation
            # Event 1037 = Stage 3 / Mitigation 3 complete
            # Event 1042 = Stage 4 / Mitigation 4 complete (SVN data written to DBX - bootmgfw.efi 7.0, cdboot.efi 3.0, wdsmgfw.efi 3.0)
            # AvailableUpdates 0x80 = Mitigation 3 triggered, 0x200 = Mitigation 4 triggered (persists across runs)
            $has1037 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1037)
            $has1042 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1042)
            # Read AvailableUpdates directly - $optInStatus isn't populated yet (Step 2.3 runs later)
            $avBits  = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty 'AvailableUpdates' -ErrorAction SilentlyContinue)
            if ($null -eq $avBits) { $avBits = 0 }
            $mit3Triggered = ($avBits -band 0x0080) -ne 0
            $mit4Triggered = ($avBits -band 0x0200) -ne 0
            if ($has1042) {
                $svnStatus.Stage = 'Stage 4'
                $svnStatus.StageDetail = 'SVN applied to DBX (Event 1042)'
            }
            elseif ($has1037) {
                $svnStatus.Stage = 'Stage 3'
                $svnStatus.StageDetail = '2011 CA revoked in DBX (Event 1037)'
            }
            elseif ($mit4Triggered -and $mit3Triggered) {
                # 0x280 in AvailableUpdates, mitigations 3+4 were triggered, pending SVN reboot
                $svnStatus.Stage = 'Stage 3+4'
                $svnStatus.StageDetail = 'Mitigations applied, pending SVN reboot'
            }
            elseif ($mit3Triggered) {
                # 0x80 in AvailableUpdates, mitigation 3 was triggered, pending SVN reboot
                $svnStatus.Stage = 'Stage 3'
                $svnStatus.StageDetail = '2011 CA revocation triggered, pending SVN reboot'
            }
            elseif ($has2023InDb) {
                $svnStatus.Stage = 'Stage 2'
                $svnStatus.StageDetail = '2023 certs in db, boot manager deployed'
            }
            else {
                $svnStatus.Stage = 'Stage 1'
                $svnStatus.StageDetail = 'Pre-deployment'
            }
            # Reboot-pending detection: compare mitigation event timestamps against last boot time
            # UEFI writes (DBX updates, SVN data) happen at OS runtime and are visible immediately,
            # but firmware doesn't enforce them until the next boot. Boot time comparison is the
            # reliable cross-reference. If events 1037/1042 fired this boot session, reboot is needed.
            # Cmdlet path (FirmwareSVN < StagedSVN) is also reliable when available.
            $svnRebootPending = $false
            $lastBootTime = $null
            try { $lastBootTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { }
            
            # FirmwareSVN < StagedSVN is a direct firmware-level reboot-pending indicator.
            # Only meaningful at Stage 3+ (after mitigations triggered). At Stage 2 the
            # mismatch is expected: boot manager writes StagedSVN but firmware won't absorb
            # until revocations happen. Both values now always come from raw-DBX (canonical),
            # so the comparison no longer needs a cmdlet-availability gate. The try/catch
            # absorbs 'N/A' string casts on pre-rollout devices.
            #
            # Floor gate: skip the comparison entirely when firmware is already at or above
            # the documented compliance floor. A higher staged SVN in that case is "future
            # work" Microsoft has shipped ahead of any actual enforcement bump.
            if (-not $svnStatus.IsCompliant -and ($mit3Triggered -or $mit4Triggered -or $has1037 -or $has1042)) {
                try {
                    $fwVer = [version]$svnStatus.FirmwareSVN
                    $stagedVer = [version]$svnStatus.StagedSVN
                    if ($fwVer -lt $stagedVer) {
                        $svnRebootPending = $true
                    }
                }
                catch { }
            }
            
            # Boot time cross-reference: if mitigation events fired since last boot, reboot is needed
            # to enforce. Catches the raw DBX path where NVRAM data appears immediately but isn't
            # enforced yet. Floor-gated on $svnStatus.IsCompliant: when firmware already meets the
            # documented compliance floor, a 1042 that fired this boot session is just absorbing
            # an already-superseded SVN bump - flagging it as "Pending SVN Reboot" produces a
            # misleading overlay on a device that's already at the enforcement target.
            if (-not $svnRebootPending -and -not $svnStatus.IsCompliant -and $null -ne $lastBootTime) {
                if ($has1042) {
                    $ev1042 = Get-LatestSecureBootEvent -CertStatus $certStatus -EventId 1042
                    if ($null -ne $ev1042 -and $ev1042.Time -gt $lastBootTime) {
                        $svnRebootPending = $true
                    }
                }
            }
            
            # Fallback: mitigation 4 triggered (0x200) but no event 1042 yet and no DBX SVN.
            # Same floor gate - a device at floor doesn't need a reboot-pending warning even
            # if the staged-task scaffolding looks mid-flight.
            if (-not $svnRebootPending -and -not $svnStatus.IsCompliant -and $mit4Triggered -and $null -eq $svnStatus.DbxSVN -and -not $has1042) {
                $svnRebootPending = $true
            }
            $svnStatus.RebootPending = $svnRebootPending
            
            # Revocation reboot detection: event 1037 fired this boot session, or mitigation 3
            # triggered but not yet processed, revocation is applied but needs reboot to enforce
            $svnStatus.RevocationAppliedPendingReboot = $false
            if ($has1037 -and $null -ne $lastBootTime) {
                $ev1037 = Get-LatestSecureBootEvent -CertStatus $certStatus -EventId 1037
                if ($null -ne $ev1037 -and $ev1037.Time -gt $lastBootTime) {
                    $svnStatus.RevocationAppliedPendingReboot = $true
                    $svnStatus.RevocationPending = $false
                }
            }
            elseif ($mit3Triggered -and -not $has1037) {
                $svnStatus.RevocationAppliedPendingReboot = $true
                $svnStatus.RevocationPending = $false
            }
            
            Write-Log "INFO" "SVN Compliance: $($svnStatus.ComplianceStatus) (source: $($svnStatus.Source)) | $($svnStatus.Stage): $($svnStatus.StageDetail)"
            # Identical SVN log shape across every stage. Firmware/Staged are raw-DBX
            # canonical values; Boot Manager comes from the cmdlet when present, 'N/A'
            # otherwise. CdBoot/WdsMgr are always raw-DBX (cmdlet doesn't expose them).
            # Same fields, same order, regardless of KB5077241 availability.
            Write-Log "INFO" "Firmware SVN: $($svnStatus.FirmwareSVN) | Boot Manager SVN: $($svnStatus.BootManagerSVN) | Staged SVN: $($svnStatus.StagedSVN) | CdBoot SVN: $($svnStatus.CdBootSVN) | WdsMgr SVN: $($svnStatus.WdsMgrSVN)"
            if ($svnStatus.RevocationPending) {
                Write-Log "INFO" "SVN non-compliance expected - PCA 2011 not yet revoked in DBX (pre-Stage 3)"
            }
            if ($svnStatus.SvnUpdatePending) {
                Write-Log "INFO" "SVN update pending - DBXUpdateSVN.bin ($($svnStatus.WindowsUpdateSVN)) not yet applied to DBX"
            }
            if ($svnStatus.RevocationAppliedPendingReboot) {
                Write-Log "WARNING" "2011 CA revocation applied (Event 1037) but not yet visible in DBX bytes (reboot required)"
            }
        }
    }
    
    # Early DBX staged-vs-firmware validation pass.
    # Purpose: the top-level state machine below (title + plaintext) needs to
    # distinguish three states beyond the existing generic "Pending SVN Reboot":
    #   * PendingUpdate    - 1-2 missing, every missing component has a prior
    #                        firmware SVN, AND firmware has not had a chance to
    #                        absorb since the last DBX write (pre-reboot state).
    #                        Benign: next boot will apply.
    #   * SvnNotApplied    - same miss pattern, BUT firmware HAS booted since
    #                        the last DBX-writing event and still refused to
    #                        absorb. Not "pending a reboot" - the reboot already
    #                        happened. This is a firmware-level refusal that
    #                        operators need to escalate (OEM BIOS update / support).
    #                        Diagnosed via lastBootTime > latest(1034, 1042).
    #   * (all 3 missing or asymmetric absent FirmwareSvn) - handled by the
    #                        generic RebootPending / PartialCommit paths.
    # All three are only reliably distinguishable thanks to the raw-DBX max-SVN
    # fix (see Get-DbxBootMgrSVN / PowerShell#27058). Compute once here; the
    # gating site further down reuses the cached result.
    $dbxValidationResult = $null
    if ($secureBoot -eq 'Enabled' -and $null -ne $dbxBytes) {
        $dbxValidationResult = Compare-DbxAgainstStagedBins -DbxBytes $dbxBytes
    }
    if ($null -ne $svnStatus) {
        $svnStatus.PendingUpdate                = $false
        $svnStatus.PendingUpdateComponents      = @()
        $svnStatus.SvnNotApplied                = $false
        $svnStatus.SvnNotAppliedComponents      = @()
        $svnStatus.LastDbxWriteAfterBoot        = $false
        if ($null -ne $dbxValidationResult -and $dbxValidationResult.Succeeded) {
            $svnMissEarly = @($dbxValidationResult.MissingComponents)
            if ($svnMissEarly.Count -gt 0 -and $svnMissEarly.Count -lt 3) {
                $everyPrior = $true
                foreach ($m in $svnMissEarly) {
                    if ([string]::IsNullOrWhiteSpace([string]$m.FirmwareSvn)) { $everyPrior = $false; break }
                }
                if ($everyPrior) {
                    # Firmware-had-a-chance cross-reference:
                    #   latest DBX-modification event time  <  last boot time
                    # means the firmware booted AFTER the scheduled task wrote the
                    # update to NVRAM. If firmware still hasn't absorbed, it's a
                    # refusal. Uses 1034 (DBX variable applied, fires on every scheduled-task
                    # DBX commit) and 1042 (Mitigation-4 SVN applied, one-shot).
                    $lastDbxWrite = $null
                    foreach ($evtId in @(1034, 1042)) {
                        $evt = Get-LatestSecureBootEvent -CertStatus $certStatus -EventId $evtId
                        if ($null -ne $evt -and $null -ne $evt.Time) {
                            if ($null -eq $lastDbxWrite -or $evt.Time -gt $lastDbxWrite) {
                                $lastDbxWrite = $evt.Time
                            }
                        }
                    }
                    $firmwareHadChance = $false
                    if ($null -ne $lastBootTime -and $null -ne $lastDbxWrite -and $lastBootTime -gt $lastDbxWrite) {
                        $firmwareHadChance = $true
                    }
                    $comps = @($svnMissEarly | ForEach-Object { $_.Component })
                    if ($firmwareHadChance) {
                        $svnStatus.SvnNotApplied           = $true
                        $svnStatus.SvnNotAppliedComponents = $comps
                    }
                    else {
                        $svnStatus.PendingUpdate           = $true
                        $svnStatus.PendingUpdateComponents = $comps
                    }
                }
            }
        }
        
        # Reboot-awareness aware "SVN update state" log. Emitted here (after the
        # DBX early pass) rather than inside the $svnStatus decoration block so
        # the wording can reflect the component-level + lastBootTime analysis.
        # Suppresses the older generic "SVN reboot pending - reboot required"
        # WARNING which was misleading after a reboot had already happened.
        if ($svnStatus.SvnNotApplied) {
            $comps = @($svnStatus.SvnNotAppliedComponents) -join ', '
            Write-Log "WARNING" "SVN update NOT applied after reboot for component(s): $comps. Firmware booted since the last DBX write (Event 1034/1042) and still refused to absorb. Investigate OEM BIOS/firmware update or support escalation - rebooting again will not resolve."
        }
        elseif ($svnStatus.PendingUpdate) {
            $comps = @($svnStatus.PendingUpdateComponents) -join ', '
            Write-Log "INFO" "Pending SVN update for component(s): $comps. Firmware at prior SVN; scheduled task wrote the next increment to DBX and firmware will attempt to absorb on next boot."
        }
        elseif ($svnStatus.RebootPending) {
            # Generic fallback - 3-of-3 missing, or cmdlet-path RebootPending without
            # component-level detail. Preserves the original WARNING semantics for
            # any reboot-pending state that isn't a narrower PendingUpdate / NotApplied.
            Write-Log "WARNING" "SVN reboot pending - firmware SVN has not yet absorbed the staged update (reboot required)"
        }
    }
    
    # =======================================================================
    # Step 2.18: HP-specific BIOS CA 2023 interface check
    # =======================================================================
    # Vendor branch. HP devices have three findings that shape the current policy:
    #   1. Many HP firmwares do NOT expose the three "Windows UEFI CA 2023",
    #      "Microsoft Option ROM UEFI CA 2023", "Microsoft UEFI CA 2023"
    #      toggles. SetBIOSSetting returns rc=4 for these. Devices where only
    #      'Enable MS UEFI CA key' is exposed still reach Event 1808 once that
    #      one is set to 'Yes'. The "missing" toggles are not a problem on these.
    #   2. BitLocker recovery is triggered by a BIOS write (the change
    #      moves the PCRs the next boot measures against), not by event-log
    #      history. Suspend must therefore be gated on writes-made and not on the
    #      stuck-pattern filter.
    #   3. Some devices keep a stale 1796 in the event log after reaching
    #      1808. The filter must suppress in that case (handled in
    #      Test-HpStuckEventPattern via the EventId==1808 freshness gate).
    #
    # Remediation policy:
    #   - The BIOS write fires ONLY under the Enable opt-in action
    #     ($script:IsEnableAction). Audit is read-only and Remove opt-in is the
    #     opposite intent (tearing down WU management), so neither writes
    #     firmware toggles. NonCompliant (Present-but-wrong) settings are
    #     written via SetBIOSSetting; NotExposed settings are skipped entirely
    #     - the firmware lacks them and rc=4 is not actionable.
    #   - Set-HpBiosCa2023Settings decides BitLocker suspend internally:
    #     fires iff at least one SetBIOSSetting returned rc=0.
    #   - Test-HpStuckEventPattern still runs, but ONLY influences the card
    #     wording (red Action Required vs amber latent risk vs amber filter-
    #     not-matched). It no longer drives any code paths.
    # =======================================================================
    $hpBios            = $null
    $hpStuckPattern    = $false
    $hpRemediation     = $null
    $isHpManufacturer  = $false
    if ($secureBoot -eq 'Enabled') {
        $hpManufacturerName = $null
        try {
            $hpManufacturerName = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).Manufacturer
        }
        catch {
            Write-Log "INFO" "Win32_BIOS lookup for HP detection failed: $($_.Exception.Message)"
        }
        if ($hpManufacturerName -match '(?i)HP|Hewlett-Packard') {
            $isHpManufacturer = $true
            Write-Host "`n === HP BIOS CA 2023 Interface Check ==="
            Write-Log "INFO" "HP manufacturer detected ($hpManufacturerName); inspecting CA 2023 BIOS toggles"
            $hpBios = Get-HpBiosCa2023Settings
            if ($hpBios.Available) {
                if (@($hpBios.NotExposed).Count -gt 0) {
                    Write-Log "INFO" "HP BIOS toggles not exposed by this firmware (will be skipped): $($hpBios.NotExposed -join ', ')"
                }
                $hpStuckPattern = Test-HpStuckEventPattern -CertStatus $certStatus -AvailableUpdatesBits ([int]$avBits)
                if ($hpBios.AllCompliant) {
                    Write-Log "SUCCESS" "All exposed HP CA 2023 BIOS toggles already in expected enabled state - no write needed"
                }
                else {
                    Write-Log "WARNING" "HP CA 2023 BIOS toggles non-compliant (and exposed): $($hpBios.NonCompliant -join ', ')"
                    if ($hpStuckPattern) {
                        Write-Log "WARNING" "HP stuck-state signature confirmed (1796 + 1800 + 1801 repeating$(if ($avBits -eq 0x4500) { ' / AvailableUpdates=0x4500' } else { '' }))"
                    }
                    else {
                        Write-Log "INFO" "Stuck-state event filter did not match - filter only influences card wording, BIOS write still applies"
                    }
                    # HP BIOS toggle remediation is a write that can move the
                    # boot-measured PCRs - only ever fire it under the Enable
                    # opt-in action. Audit is read-only; Remove opt-in is the
                    # opposite intent (tearing down WU management) and must not
                    # be flipping firmware toggles on.
                    if ($script:IsEnableAction) {
                        Write-Log "INFO" "Applying HP BIOS remediation: SetBIOSSetting on $($hpBios.NonCompliant.Count) non-compliant exposed toggle(s). BitLocker suspend will fire iff any write returns rc=0."
                        $hpRemediation = Set-HpBiosCa2023Settings -NamesToFix $hpBios.NonCompliant
                    }
                    elseif ($script:IsAuditAction) {
                        Write-Log "INFO" "Audit mode - skipping BIOS write. Re-run with 'Enable opt-in' to apply remediation."
                    }
                    else {
                        Write-Log "INFO" "Action '$SecureBootAction' is not 'Enable opt-in' - skipping HP BIOS write (remediation only runs under Enable opt-in)."
                    }
                }
            }
            else {
                Write-Log "INFO" "HP_BIOSSetting WMI unavailable - cannot inspect HP CA 2023 BIOS toggles on this device"
            }
            Write-Host ""
        }
    }
    
    # =======================================================================
    # Step 2.2: SVN Enforcement (when $EnforceSvnCompliance -eq 'Enforce SVN')
    # =======================================================================
    # Applies KB5025885 mitigations sequentially (CVE-2023-24932 enterprise guidance):
    #   Mitigation 1 (0x40)  : Add Windows UEFI CA 2023 to DB
    #   Mitigation 2 (0x100) : Install 2023-signed boot manager
    #   Mitigation 3 (0x80)  : Revoke PCA 2011 in DBX
    #   Mitigation 4 (0x200) : Apply SVN to DBX firmware
    # Combined 3+4 (0x280) per CVE-2023-24932 enterprise guidance when both needed - single reboot.
    # Each step checks current state first (idempotent).
    # Source: https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d
    # Source: https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967
    # =======================================================================
    $svnEnforcementResult = $null
    $svnBitLockerSafetyResult = $null
    if ($secureBoot -eq 'Enabled') {
        $svnBitLockerSafetyResult = New-SvnBitLockerSafetyResult `
            -Enabled ([bool]$SuspendBitlockerForSVN) `
            -RebootCount 2
        
        # Handle pre-existing Stage 3/4 bits before Enforce mode can trigger the
        # Secure-Boot-Update task. Unsafe premature bits are cleared first. Any
        # unapplied bits that remain receive the same BitLocker protection in
        # Enforce and Passive/Audit modes.
        $preExistingSvnPrereqs = Test-SvnStagePrerequisites -Has2023InDb $has2023InDb -CertStatus $certStatus
        if (-not $preExistingSvnPrereqs.AllPrereqsMet -and
            ($preExistingSvnPrereqs.Stage3BitPending -or $preExistingSvnPrereqs.Stage4BitPending)) {
            Write-Log "WARNING" "Shared SVN safety: Premature Stage 3/4 bits detected before mode processing; attempting repair first"
            $svnRepairResult = Repair-SvnEnforcement -Has2023InDb $has2023InDb -CertStatus $certStatus
            $preExistingSvnPrereqs = Test-SvnStagePrerequisites -Has2023InDb $has2023InDb -CertStatus $certStatus
        }
        
        $preExistingPendingStages = @()
        if ($preExistingSvnPrereqs.Stage3BitPending) { $preExistingPendingStages += 'Stage 3' }
        if ($preExistingSvnPrereqs.Stage4BitPending) { $preExistingPendingStages += 'Stage 4' }
        if ($preExistingPendingStages.Count -gt 0) {
            Write-Log "WARNING" "Shared SVN safety: Pre-existing $($preExistingPendingStages -join ' + ') manifest bits detected; preparing BitLocker before mode processing"
            $svnBitLockerSafetyResult = Suspend-SystemBitLockerVolumesForSvn `
                -Enabled ([bool]$SuspendBitlockerForSVN) `
                -RebootCount 2 `
                -Stages $preExistingPendingStages
            $svnBitLockerSafetyResult.PendingManifest = $true
            if (-not $preExistingSvnPrereqs.AllPrereqsMet) {
                $svnBitLockerSafetyResult.UnsafePendingManifest = $true
                $svnBitLockerSafetyResult.Status = 'UnsafeManifest'
                $svnBitLockerSafetyResult.CanProceed = $false
                Write-Log "ERROR" "Shared SVN safety: Premature Stage 3/4 bits could not be cleared. No Secure Boot task will be triggered; DO NOT REBOOT."
            }
            elseif (-not $svnBitLockerSafetyResult.CanProceed) {
                Write-Log "ERROR" "Shared SVN safety: Stage 3/4 bits remain pending, but BitLocker suspension failed. No Secure Boot task will be triggered; DO NOT REBOOT."
            }
        }
    }
    $enforceMissingOptIn  = $false
    if ($EnforceSvnCompliance -eq 'Enforce SVN' -and $secureBoot -eq 'Enabled') {
        # Check if opt-in is set (Step 2.3 hasn't run yet, read directly)
        # Only warn when certs are missing AND not pending install, if certs are in db or a reboot
        # will deliver them, enforcement handles stage pushing directly via AvailableUpdates.
        $earlyOptIn = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue |
                       Select-Object -ExpandProperty 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue)
        $certsPendingOrPresent = ($has2023InDb -or ($null -ne $certStatus -and $certStatus.EventId -in @(1800, 1799, 1808)))
        if (($null -eq $earlyOptIn -or $earlyOptIn -eq 0) -and -not $certsPendingOrPresent) {
            $enforceMissingOptIn = $true
            Write-Log "WARNING" "SVN Enforcement is enabled but WU Secure Boot management is NOT opted in and 2023 certs are not in db. Set securebootAction to 'Enable opt-in' for full deployment."
        }
        Write-Host "`n ==================================================================="
        Write-Host " ===    SVN Enforcement Mode - Applying KB5025885 Mitigations    ==="
        Write-Host " ==================================================================="
        $svnEnforcementResult = Invoke-SvnEnforcement `
            -Has2023InDb      $has2023InDb `
            -Has2023InKek     $has2023InKek `
            -SvnStatus        $svnStatus `
            -CertStatus       $certStatus `
            -DbxBytes         $dbxBytes `
            -Ca2011RevokedInDbx $ca2011RevokedInDbx `
            -DbCertsFound     $dbCertsFound `
            -SuspendBitlockerForSVN ([bool]$SuspendBitlockerForSVN) `
            -InitialBitLockerSuspension $svnBitLockerSafetyResult
        
        # Re-query event log after enforcement to capture new events (1037, 1042, etc.)
        # This ensures the event log summary and card show the full up-to-date picture
        if ($null -ne $svnEnforcementResult -and $svnEnforcementResult.ActionsApplied.Count -gt 0) {
            $postEnforcementStatus = Get-CertUpdateEventStatus
            if ($null -ne $postEnforcementStatus -and $null -ne $postEnforcementStatus.AllEvents) {
                $certStatus = $postEnforcementStatus
                Write-Log "INFO" "Event log re-queried after enforcement: $($certStatus.AllEvents.Count) event(s)"
            }
        }
        
        # Re-read db certs after enforcement if supplementary certs were attempted
        # This ensures the cert inventory card reflects newly-applied variable certs
        if ($null -ne $svnEnforcementResult -and $svnEnforcementResult.SupplementaryCertsAttempted) {
            Write-Log "INFO" "Re-reading db certs after supplementary cert application"
            try {
                $postEnfDb = Get-UefiDatabaseCerts -Name db
                $postEnfDbCerts = @($postEnfDb.Certs | Where-Object {
                    $_.Subject -match '2023'
                } | ForEach-Object {
                    if ($_.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() }
                })
                if ($postEnfDbCerts.Count -gt $dbCertsFound.Count) {
                    $newCerts = @($postEnfDbCerts | Where-Object { $dbCertsFound -notcontains $_ })
                    Write-Log "SUCCESS" "Post-enforcement db update: +$($newCerts -join ', ') (was: $($dbCertsFound -join ', '))"
                    $dbCertsFound = $postEnfDbCerts
                    $has2023InDb = $dbCertsFound -contains 'Windows UEFI CA 2023'
                    $allDbCertsPresent = ($dbCertsFound.Count -eq $updatedDbCertNames.Count)
                }
            }
            catch {
                Write-Log "WARNING" "Failed to re-read db certs after enforcement: $($_.Exception.Message)"
            }
        }
        
        # Update SVN stage and revocation status after enforcement
        if ($null -ne $svnEnforcementResult -and $svnEnforcementResult.ActionsApplied.Count -gt 0 -and $null -ne $svnStatus) {
            if ($svnEnforcementResult.Mitigation4 -in @('Applied','AlreadyApplied') -and
                $svnEnforcementResult.Mitigation3 -in @('Applied','AlreadyApplied')) {
                if ($svnEnforcementResult.RebootRequired) {
                    $svnStatus.Stage = 'Stage 3+4'
                    $svnStatus.StageDetail = 'Mitigations applied, pending SVN reboot'
                }
                else {
                    $svnStatus.Stage = 'Stage 4'
                    $svnStatus.StageDetail = 'SVN applied to DBX (enforcement complete)'
                }
            }
            elseif ($svnEnforcementResult.Mitigation3 -in @('Applied','AlreadyApplied')) {
                if ($svnEnforcementResult.RebootRequired) {
                    $svnStatus.Stage = 'Stage 3'
                    $svnStatus.StageDetail = '2011 CA revocation applied, pending SVN reboot'
                }
                else {
                    $svnStatus.Stage = 'Stage 3'
                    $svnStatus.StageDetail = '2011 CA revoked in DBX (enforcement complete)'
                }
            }
            # Update revocation flag - if mitigation 3 was just applied, the revocation
            # is no longer "pending" (waiting for MS to do it), it's been applied but may need reboot
            if ($svnEnforcementResult.Mitigation3 -eq 'Applied') {
                $svnStatus.RevocationPending = $false
                $svnStatus.RevocationAppliedPendingReboot = $true
            }
            elseif ($svnEnforcementResult.Mitigation3 -eq 'AlreadyApplied') {
                $svnStatus.RevocationPending = $false
            }
            # Re-read DBX SVN if mitigation 4 was just applied
            if ($svnEnforcementResult.Mitigation4 -eq 'Applied') {
                $newDbxBytes = (Get-UefiDatabaseCerts -Name dbx).Bytes
                $newDbxSvn = Get-DbxBootMgrSVN -DbxBytes $newDbxBytes
                if ($null -ne $newDbxSvn) {
                    $svnStatus.DbxSVN = $newDbxSvn
                    Write-Log "INFO" "Post-enforcement DBX SVN: $newDbxSvn"
                }
            }
        }
        Write-Host ""
    }
    elseif ($EnforceSvnCompliance -eq 'Passive' -and $secureBoot -eq 'Enabled') {
        Write-Log "INFO" "SVN Enforcement: Passive mode - audit only (Microsoft enforcement: June 2026 - 2027)"
        # Pre-existing pending-bit repair and BitLocker preparation already ran
        # in the shared pre-mode safety pass above. No SVN enforcement is initiated.
    }

    # =======================================================================
    # FINAL SHARED STAGE 3/4 BITLOCKER SAFETY RECONCILIATION
    # =======================================================================
    # This pass is deliberately outside the Enforce/Passive branches. It catches
    # Stage 3/4 manifest bits written by this script, Windows Update, policy, or
    # another management tool. The shared pre-mode pass already repaired and
    # protected pre-existing bits; this final pass captures bits written or changed
    # during active processing without enabling SVN enforcement in Passive mode.
    if ($secureBoot -eq 'Enabled') {
        if ($null -ne $svnEnforcementResult) {
            $svnBitLockerSafetyResult = $svnEnforcementResult.BitLockerSuspension
        }
        
        $sharedSvnPrereqs = Test-SvnStagePrerequisites -Has2023InDb $has2023InDb -CertStatus $certStatus
        if (-not $sharedSvnPrereqs.AllPrereqsMet -and
            ($sharedSvnPrereqs.Stage3BitPending -or $sharedSvnPrereqs.Stage4BitPending) -and
            -not $svnBitLockerSafetyResult.UnsafePendingManifest) {
            Write-Log "WARNING" "Final shared SVN safety: Newly detected premature Stage 3/4 bits require repair"
            $svnRepairResult = Repair-SvnEnforcement -Has2023InDb $has2023InDb -CertStatus $certStatus
            $sharedSvnPrereqs = Test-SvnStagePrerequisites -Has2023InDb $has2023InDb -CertStatus $certStatus
        }
        
        $sharedPendingStages = @()
        if ($sharedSvnPrereqs.Stage3BitPending) { $sharedPendingStages += 'Stage 3' }
        if ($sharedSvnPrereqs.Stage4BitPending) { $sharedPendingStages += 'Stage 4' }
        
        if ($sharedPendingStages.Count -gt 0) {
            $safetyAlreadyHandled = ($null -ne $svnBitLockerSafetyResult -and
                                     $svnBitLockerSafetyResult.Status -ne 'NotRequired')
            if (-not $safetyAlreadyHandled) {
                Write-Log "WARNING" "Shared SVN safety: Pending $($sharedPendingStages -join ' + ') manifest bits detected; preparing BitLocker regardless of enforcement mode"
                $svnBitLockerSafetyResult = Suspend-SystemBitLockerVolumesForSvn `
                    -Enabled ([bool]$SuspendBitlockerForSVN) `
                    -RebootCount 2 `
                    -Stages $sharedPendingStages
            }
            
            $svnBitLockerSafetyResult.PendingManifest = $true
            if (-not $sharedSvnPrereqs.AllPrereqsMet) {
                $svnBitLockerSafetyResult.UnsafePendingManifest = $true
                $svnBitLockerSafetyResult.Status = 'UnsafeManifest'
                $svnBitLockerSafetyResult.CanProceed = $false
            }
            
            if ($null -ne $svnEnforcementResult) {
                $svnEnforcementResult.BitLockerSuspension = $svnBitLockerSafetyResult
            }
            
            if ($svnBitLockerSafetyResult.UnsafePendingManifest) {
                Write-Log "ERROR" "Shared SVN safety: Unsafe Stage 3/4 bits remain after repair. DO NOT REBOOT until resolved."
            }
            elseif (-not $svnBitLockerSafetyResult.CanProceed) {
                Write-Log "ERROR" "Shared SVN safety: Stage 3/4 bits remain pending, but BitLocker suspension failed. DO NOT REBOOT until resolved."
            }
        }
    }
    # =======================================================================
    # END FINAL SHARED STAGE 3/4 BITLOCKER SAFETY RECONCILIATION
    # =======================================================================
    
    # -----------------------------------------------
    # Step 2.25: Execute SecureBootAction if specified
    # -----------------------------------------------
    if ($SecureBootAction) {
        Write-Host "`n === Secure Boot Action: $SecureBootAction ==="
        
        if ($secureBoot -ne 'Enabled') {
            Write-Log "WARNING" "Secure Boot is '$secureBoot'; action '$SecureBootAction' requires Secure Boot to be enabled. Skipping action."
        }
        else {
            switch ($SecureBootAction) {
                'Enable opt-in for SecureBoot management' {
                    # Note if already compliant
                    if ($certStatus -and $certStatus.EventId -eq 1808) {
                        Write-Log "INFO" "Event 1808 already present (compliant). Enablement is not strictly necessary, but proceeding to ensure keys are set."
                    }
                    
                    # 1. Set required telemetry (machine + per-user)
                    Enable-RequiredTelemetry
                    
                    # 2. Set opt-in gate key (MicrosoftUpdateManagedOptIn only - no stage pushing)
                    Set-SecureBootOptInKeys
                    
                    # 3. Trigger Secure-Boot-Update scheduled task to nudge Windows Update
                    Trigger-SecureBootTask
                    
                    Write-Log "SUCCESS" "Secure Boot opt-in and telemetry enablement complete"
                }
                'Remove opt-in for SecureBoot management' {
                    if ($certStatus -and $certStatus.EventId -eq 1808) {
                        Write-Log "INFO" "Event 1808 present (compliant). Removal will opt out of future WU-managed updates, but the current cert rotation is already complete."
                    }
                    
                    # 1. Remove telemetry enforcement
                    Remove-TelemetryEnforcement
                    
                    # 2. Remove opt-in gate (leave AvailableUpdates alone)
                    Remove-SecureBootOptInKeys
                    
                    Write-Log "SUCCESS" "Secure Boot opt-out and telemetry enforcement removal complete"
                }
                'Audit SecureBoot management status' {
                    Write-Log "INFO" "Auditing Secure Boot management configuration (read-only)"
                    
                    # --- Machine-level telemetry ---
                    $dataCollectionPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
                    $allowTelemetry = (Get-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue |
                                       Select-Object -ExpandProperty "AllowTelemetry" -ErrorAction SilentlyContinue)
                    $maxTelemetry   = (Get-ItemProperty -Path $dataCollectionPath -Name "MaxTelemetryAllowed" -ErrorAction SilentlyContinue |
                                       Select-Object -ExpandProperty "MaxTelemetryAllowed" -ErrorAction SilentlyContinue)
                    
                    if ($null -eq $allowTelemetry) {
                        Write-Log "INFO" "AllowTelemetry: Not set (OS default)"
                    }
                    else {
                        $telemetryLabel = switch ($allowTelemetry) { 0 { 'Off' } 1 { 'Required' } 2 { 'Enhanced' } 3 { 'Full' } default { $allowTelemetry } }
                        Write-Log "INFO" "AllowTelemetry: $allowTelemetry ($telemetryLabel)"
                    }
                    
                    if ($null -eq $maxTelemetry) {
                        Write-Log "INFO" "MaxTelemetryAllowed: Not set (OS default)"
                    }
                    else {
                        $maxLabel = switch ($maxTelemetry) { 0 { 'Off' } 1 { 'Required' } 2 { 'Enhanced' } 3 { 'Full' } default { $maxTelemetry } }
                        Write-Log "INFO" "MaxTelemetryAllowed: $maxTelemetry ($maxLabel)"
                    }
                    
                    $telemetryMeetsMin = ($null -ne $allowTelemetry -and $allowTelemetry -ge 1) -or ($null -eq $allowTelemetry)
                    if (-not $telemetryMeetsMin) {
                        Write-Log "WARNING" "AllowTelemetry is 0 (Off) - Windows Update cannot manage Secure Boot certs"
                    }
                    
                    # --- Secure Boot opt-in keys ---
                    $secureBootPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
                    $optIn = (Get-ItemProperty -Path $secureBootPath -Name "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue |
                              Select-Object -ExpandProperty "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue)
                    $available = (Get-ItemProperty -Path $secureBootPath -Name "AvailableUpdates" -ErrorAction SilentlyContinue |
                                  Select-Object -ExpandProperty "AvailableUpdates" -ErrorAction SilentlyContinue)
                    
                    if ($optIn -eq 0x5944) {
                        Write-Log "INFO" "MicrosoftUpdateManagedOptIn: 0x5944 (Opted in to Windows Update Secure Boot management)"
                    }
                    elseif ($null -eq $optIn) {
                        Write-Log "INFO" "MicrosoftUpdateManagedOptIn: Not set (not opted in)"
                    }
                    else {
                        Write-Log "INFO" "MicrosoftUpdateManagedOptIn: $optIn (unexpected value)"
                    }
                    
                    if ($available -eq 0x5944) {
                        Write-Log "INFO" "AvailableUpdates: 0x5944 (update trigger set)"
                    }
                    elseif ($null -eq $available) {
                        Write-Log "INFO" "AvailableUpdates: Not set (no trigger)"
                    }
                    else {
                        Write-Log "INFO" "AvailableUpdates: $available"
                    }
                    
                    # --- Summary ---
                    $isOptedIn = $optIn -eq 0x5944
                    if ($isOptedIn -and $telemetryMeetsMin) {
                        Write-Log "SUCCESS" "Secure Boot management via Windows Update: ENABLED (opted in + telemetry meets minimum)"
                    }
                    elseif ($isOptedIn -and -not $telemetryMeetsMin) {
                        Write-Log "WARNING" "Secure Boot management via Windows Update: OPT-IN SET but telemetry is too low (AllowTelemetry=0)"
                    }
                    else {
                        Write-Log "INFO" "Secure Boot management via Windows Update: NOT ENABLED (opt-in key not set)"
                    }
                }
            }
        }
        Write-Host ""
    }
    
    # -----------------------------------------------
    # Step 2.3: Check opt-in status (always, after any action has run)
    # -----------------------------------------------
    $optInStatus = $null
    if ($secureBoot -eq 'Enabled') {
        Write-Host "`n === Opt-In Status Check ==="
        $optInStatus = Check-OptInStatus
        
        # Re-evaluate $enforceMissingOptIn with fresh opt-in status.
        # The earlier computation at the Enforcement block captured state BEFORE Step 2 actions ran;
        # if 'Enable opt-in for SecureBoot management' was invoked this run, opt-in is now set
        # and the stale warning must not appear in the card or SecureBootStatus field.
        if ($EnforceSvnCompliance -eq 'Enforce SVN') {
            $certsPendingOrPresent = ($has2023InDb -or ($null -ne $certStatus -and $certStatus.EventId -in @(1800, 1799, 1808)))
            $enforceMissingOptIn = ((-not $optInStatus.IsOptedIn) -and -not $certsPendingOrPresent)
        }
        else {
            $enforceMissingOptIn = $false
        }
        
        $telemetryLabel = if ($null -eq $optInStatus.AllowTelemetry) { 'Not set (OS default)' }
                          else { switch ($optInStatus.AllowTelemetry) { 0 { '0 (Off)' } 1 { '1 (Required)' } 2 { '2 (Enhanced)' } 3 { '3 (Full)' } default { $optInStatus.AllowTelemetry } } }
        Write-Log "INFO" "AllowTelemetry: $telemetryLabel"
        
        if ($optInStatus.IsOptedIn) {
            Write-Log "INFO" "MicrosoftUpdateManagedOptIn: 0x5944 (opted in)"
        }
        else {
            Write-Log "INFO" "MicrosoftUpdateManagedOptIn: $(if ($null -eq $optInStatus.OptInValue) { 'Not set' } else { $optInStatus.OptInValue }) (not opted in)"
        }
        
        if ($optInStatus.AvailableUpdatesSet) {
            $avHex = '0x{0:X}' -f $optInStatus.AvailableUpdates
            Write-Log "INFO" "AvailableUpdates: $avHex (trigger set)"
        }
        else {
            Write-Log "INFO" "AvailableUpdates: $(if ($null -eq $optInStatus.AvailableUpdates) { 'Not set' } else { $optInStatus.AvailableUpdates })"
        }
        
        # AvailableUpdatesPolicy (GPO/MDM-driven, persists across reboots)
        if ($optInStatus.AvailableUpdatesPolicySet) {
            $apHex = '0x{0:X}' -f $optInStatus.AvailableUpdatesPolicy
            Write-Log "INFO" "AvailableUpdatesPolicy: $apHex (GPO/MDM policy set)"
        }
        elseif ($null -ne $optInStatus.AvailableUpdatesPolicy) {
            Write-Log "INFO" "AvailableUpdatesPolicy: $($optInStatus.AvailableUpdatesPolicy)"
        }
        
        # HighConfidenceOptOut
        if ($null -ne $optInStatus.HighConfidenceOptOut) {
            if ($optInStatus.HighConfidenceOptOut -ne 0) {
                Write-Log "WARNING" "HighConfidenceOptOut: $($optInStatus.HighConfidenceOptOut) - device is opted OUT of auto-deployment"
            } else {
                Write-Log "INFO" "HighConfidenceOptOut: 0 (not opted out)"
            }
        }
        
        # Decoded bitmask meaning
        if ($optInStatus.AvailableUpdatesMeaning.Count -gt 0 -and $optInStatus.EffectiveAvailable -ne 0) {
            Write-Log "INFO" "Requested updates: $($optInStatus.AvailableUpdatesMeaning -join '; ')"
        }
        
        switch ($optInStatus.Summary) {
            'Enabled'     { Write-Log "SUCCESS" "Windows Update Secure Boot management: Enabled" }
            'Blocked'     { Write-Log "WARNING" "Windows Update Secure Boot management: Opted in but telemetry too low (AllowTelemetry=0)" }
            'Not enabled' { Write-Log "INFO" "Windows Update Secure Boot management: Not enabled (opt-in key not set)" }
        }
        Write-Host ""
    }
    
    # -----------------------------------------------
    # Step 2.5: Automate registry trigger if needed
    # -----------------------------------------------
    # IMPORTANT: This step only runs when SecureBootAction is 'Enable opt-in for SecureBoot management'.
    # In Audit mode, this step is skipped entirely. No registry writes, no task triggers.
    # Windows will NOT update the CA2023 certificates without opt-in (MicrosoftUpdateManagedOptIn = 0x5944).
    # Microsoft's automatic enforcement begins June 2026 and ramps through 2027.
    $triggeredOsUpdate = $false
    $postTriggerState  = $null
    if ($SecureBootAction -eq 'Enable opt-in for SecureBoot management') {
        # Trigger conditions (when servicing hasn't already confirmed Updated):
        #   A) 2023 cert is in db but OS hasn't confirmed via 1808 (stale 1801 or no events)
        #   B) Cert in dbDefault, KEK missing, no Event 1803 blocker - opt-in can push KEK + certs
        # Skip trigger if 1800 (reboot required) or 1799 (boot manager installed) - these are in-progress states
        # that re-triggering cannot advance; they need time, sometimes up to 9+ days
        $servicingAlreadyUpdated = ($null -ne $servicingStatus -and $servicingStatus.UEFICA2023Status -eq 'Updated')
        $has1803InLog = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1803)
        $canTrigger = $secureBoot -eq 'Enabled' -and -not $servicingAlreadyUpdated -and $certStatus.EventId -notin @(1808, 1800, 1799)
        $triggerReasonA = $canTrigger -and $has2023InDb
        $triggerReasonB = $canTrigger -and -not $has2023InDb -and ($has2023InDbDefault -or -not $has2023InKek) -and -not $has1803InLog
        if ($triggerReasonA -or $triggerReasonB) {
            if ($triggerReasonA -and $certStatus.Status -eq 'ActionRequired') {
                Write-Log "INFO" "2023 cert in db but stale 1801; attempting to trigger OS update"
            }
            elseif ($triggerReasonA) {
                Write-Log "INFO" "2023 cert in db but no events logged; attempting to trigger OS update"
            }
            else {
                Write-Log "INFO" "KEK/certs missing (no 1803 blocker); setting opt-in to let Windows Update push KEK + certs"
            }
            $setReg     = Set-SecureBootOptInKeys
            $appliedWcs = Apply-WinCsFeatureKey
            $triggeredOsUpdate = $setReg -or $appliedWcs
            if ($triggeredOsUpdate) {
                $taskTriggered = Trigger-SecureBootTask
                if ($taskTriggered) {
                    Write-Log "INFO" "Waiting 60 seconds to check for post-trigger events"
                    Start-Sleep -Seconds 60
                    $postTriggerState = Check-PostTriggerEvents -Minutes 2  # Check last 2 min for safety
                    Write-Log "INFO" "Post-trigger event state: $postTriggerState"
                    
                    # Re-check servicing registry - it's the definitive signal
                    $postTriggerServicing = Get-SecureBootServicingStatus
                    if ($postTriggerServicing.UEFICA2023Status -eq 'Updated') {
                        Write-Log "INFO" "Servicing registry now reports 'Updated' - overriding to Compliant"
                        $postTriggerState = 'Compliant'
                        $servicingStatus  = $postTriggerServicing
                    }
                }
            }
        }
    }
    elseif ($secureBoot -eq 'Enabled' -and $null -ne $optInStatus -and -not $optInStatus.IsOptedIn) {
        # Audit mode: warn that Windows will not update CA2023 without opt-in
        $servicingAlreadyUpdated = ($null -ne $servicingStatus -and $servicingStatus.UEFICA2023Status -eq 'Updated')
        if (-not $servicingAlreadyUpdated -and $certStatus.EventId -notin @(1808, 1799)) {
            Write-Log "WARNING" "SecureBootAction is 'Audit' (read-only). Windows may not update CA2023 certificates without opt-in. Set action to 'Enable opt-in for SecureBoot management' to allow automatic deployment."
        }
    }
    
    # -----------------------------------------------
    # Step 2.6: 1799 without 1808 - informational note
    #           Servicing confirms Updated but 1808 hasn't appeared in the event log.
    #           The Secure-Boot-Update task runs at startup + every 12 hours and is
    #           expected to produce 1808 on its next cycle(s). No action needed, only annotate.
    # -----------------------------------------------
    $pending1808Note = $false
    if ($secureBoot -eq 'Enabled' -and $certStatus.EventId -eq 1799 -and $servicingAlreadyUpdated) {
        $pending1808Note = $true
        Write-Log "INFO" "Event 1799 is latest, servicing confirms Updated - 1808 expected on next scheduled task cycle(s)"
    }
    
}

# =========================================
# END Block: State Mapping, Card Building & Output
#   Steps 3-6: Final state resolution, HTML/local card,
#   NinjaRMM custom field writes, console summary
# =========================================
end {
    # -----------------------------------------------
    # Step 3: Map to one of the 7 final states
    # -----------------------------------------------
    # Pre-compute cert labels for clear messaging
    $dbCertLabel = if ($dbCertsFound.Count -gt 0) {
        ($dbCertsFound | ForEach-Object { $_ -replace 'Microsoft ', '' -replace 'Windows ', '' }) -join ', '
    }
    else { 'None' }
    $dbDefaultCertLabel = if ($dbDefaultCertsFound.Count -gt 0) {
        ($dbDefaultCertsFound | ForEach-Object { $_ -replace 'Microsoft ', '' -replace 'Windows ', '' }) -join ', '
    }
    else { 'None' }
    
    $cardIcon        = "fas fa-shield-alt"  # Same icon for all states; color differentiates them
    $eventRowHtml    = $null                # Omitted unless Secure Boot is Enabled
    
    # PK is the blocker when: Event 1795 (firmware rejected write) is firing AND the KEK 2K CA 2023
    # is still missing from the firmware KEK database. The PK itself is a legitimate OEM cert, but
    # it does not carry the authority chain needed to authorize the new Microsoft KEK 2K CA 2023 -
    # an OEM BIOS/firmware update is required to extend PK trust. Computed here (before the state-
    # resolution switch) so the State 5b-pre-blocker case can short-circuit the "all mitigations
    # applied -> Compliant (pending 1808)" path on devices where the PK is actively blocking the
    # next KEK push. Also consumed downstream by Build-CertInventorySection to flip the PK row
    # from green check to red X and by the plaintext summary.
    # NOTE: Event 1803 is deliberately NOT a PK-blocker. 1803 means the OS could not locate a
    # PK-signed KEK 2023 update to install - the PK itself is valid, the OEM simply has not
    # published a PK-signed KEK update to Microsoft for Windows Update to serve.
    $pkBlockingKek = $false
    if ($secureBoot -eq 'Enabled' -and $pkCerts.Count -gt 0 -and $pkIsTrusted -and $null -eq $hypervisor) {
        $has1795ForPk = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1795)
        if ($has1795ForPk -and -not $has2023InKek) {
            $pkBlockingKek = $true
        }
    }
    
    # Post-compliance variable-cert refresh detection.
    # Compliance only requires the two db certs Windows UEFI CA 2023 +
    # Microsoft UEFI CA 2023 (plus KEK 2K CA 2023 for the trust chain). The
    # third db cert, Microsoft Option ROM UEFI CA 2023, is VARIABLE. A device
    # is fully compliant without it. Event 1808, then receive Event 1801 when Windows
    # Update later begins serving the Option ROM cert. Because 1801 becomes the
    # latest state event, Get-CertUpdateEventStatus reports 'ActionRequired'
    # and the card would otherwise downgrade to Pending ("stuck on 1801") even
    # though the required certs are present and the device is compliant.
    #
    # Detect that specific case so the card maintains Compliant with a
    # pending-cert note instead of a false regression:
    #   - both required certs present
    #   - KEK 2023 present (trust chain intact - rules out 1795/1803 blockers)
    #   - the Option ROM cert is the one not yet in db
    #   - history shows a prior Event 1808 (device was compliant)
    #   - the current latest state event is 1801 (the new variable-cert serve)
    $variableDbCertName  = 'Microsoft Option ROM UEFI CA 2023'
    $variableCertRefresh = $false
    if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus) {
        $requiredCertsPresent = ($dbCertsFound -contains 'Windows UEFI CA 2023') -and
                                ($dbCertsFound -contains 'Microsoft UEFI CA 2023')
        $optionalCertMissing  = ($dbCertsFound -notcontains $variableDbCertName)
        $hadPrior1808         = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1808)
        $latestIs1801         = ($certStatus.EventId -eq 1801)
        if ($requiredCertsPresent -and $has2023InKek -and $optionalCertMissing -and $hadPrior1808 -and $latestIs1801) {
            $variableCertRefresh = $true
            Write-Log "INFO" "Post-compliance variable cert refresh detected: required 2023 certs + KEK present, prior 1808, latest 1801 serving $variableDbCertName. Maintaining Compliant with pending cert note."
        }
    }
    
    switch ($true) {
      
        # State 1: Not Applicable (non-UEFI / unsupported hardware)
        ($secureBoot -eq 'NotApplicable') {
            $statusKey     = 'NotApplicable'
            $cardIconColor = '#6C757D'
            $statusRowHtml = '<i class="fas fa-ban" style="color:#6C757D;"></i> Not Applicable'
            $detailRowHtml = 'This machine does not support UEFI Secure Boot<br />(Legacy BIOS or unsupported environment).<br />Certificate update compliance is not applicable.'
            $plainText     = '[N/A] Secure Boot not supported (non-UEFI). Certificate check skipped.'
            $statusEmoji = "$($script:Emoji.QuestionWhite)"
            break
        }
        
        # State 2: Disabled (UEFI capable but Secure Boot is off)
        ($secureBoot -eq 'Disabled') {
            $statusKey     = 'Disabled'
            $cardIconColor = '#F0AD4E'
            $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Disabled'
            $detailRowHtml = 'UEFI Secure Boot is supported but currently disabled.<br />Certificate rotation compliance is not applicable<br />until Secure Boot is enabled.'
            $plainText     = "$($script:Emoji.Warning) Secure Boot disabled. Certificate update check not applicable until Secure Boot is enabled."
            $statusEmoji = "$($script:Emoji.Warning)"
            break
        }
        
        # State 2b: Virtualized (VMware / VirtualBox guest - hypervisor-managed Secure Boot)
        # Cert rotation is not the guest OS's responsibility; skip the Action Required / Pending
        # routing that would otherwise misreport a VM as broken.
        ($secureBoot -eq 'Enabled' -and $null -ne $hypervisor) {
            $statusKey     = 'Virtualized'
            $cardIconColor = '#5BC0DE'
            $statusRowHtml = "<i class='fas fa-cube' style='color:#5BC0DE;'></i> Virtualized ($hypervisor)"
            $hvGuide = switch ($hypervisor) {
                'VMware'     { '<a href="https://kb.vmware.com/s/article/2146528" target="_blank" rel="nofollow noopener noreferrer">VMware Secure Boot guidance</a>' }
                'VirtualBox' { '<a href="https://www.virtualbox.org/manual/UserManual.html#efi-secure-boot" target="_blank" rel="nofollow noopener noreferrer">VirtualBox Secure Boot guidance</a>' }
                default      { $null }
            }
            $detailRowHtml = "Secure Boot is managed by the <b>$hypervisor</b> hypervisor. " +
                             "Certificate rotation (CA 2023) is not applied from within the guest OS; " +
                             "update the VM configuration or hypervisor template to enroll 2023 keys."
            if ($null -ne $hvGuide) { $detailRowHtml += "<br />$hvGuide" }
            $plainText     = "[VM] $hypervisor guest - Secure Boot cert rotation is hypervisor-managed."
            $statusEmoji   = '[VM]'
            break
        }
        
        # State 2c: PK Untrusted (PKFail / CVE-2024-8105)
        # The Platform Key in the firmware is a publicly-known placeholder (AMI Test PK or
        # similar "DO NOT TRUST" cert). The private key is public, so the root of
        # Secure Boot's chain of trust is broken: anyone can sign KEK/db/dbx updates.
        # This overrides Compliant/Pending below because structural presence of 2023
        # certs is moot when an attacker can re-enroll arbitrary KEKs at will.
        # $null -eq $hypervisor guard is belt-and-braces against future clause reorders.
        ($secureBoot -eq 'Enabled' -and -not $pkIsTrusted -and $null -eq $hypervisor) {
            $statusKey     = 'PKUntrusted'
            $cardIconColor = '#D9534F'
            $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required <span style="color:#D9534F;">(PK Untrusted)</span>'
            
            $oemBiosGuide = Get-OemBIOSUpdateGuide
            $biosGuideHtml = if ($oemBiosGuide) {
                '<br /><a href="' + $oemBiosGuide + '" target="_blank" rel="nofollow noopener noreferrer">OEM BIOS/Firmware Update Guide</a>'
            }
            else { '' }
            
            $detailRowHtml =
                'The Platform Key (PK) in the BIOS is a publicly-known placeholder<br />' +
                '(<b>PKFail / CVE-2024-8105</b>). The private key is public, so Secure<br />' +
                'Boot''s chain of trust is effectively broken. Even with 2023 certs in<br />' +
                'db, an attacker can sign and enroll rogue KEK/db/dbx entries and<br />' +
                'persist a bootkit. A BIOS/firmware update from the OEM is required.' + $biosGuideHtml
            
            $plainText   = "$($script:Emoji.Times) Secure Boot Enabled but PK is a AMI test key (PKFail / CVE-2024-8105). Chain of trust broken. BIOS update required."
            $statusEmoji = "$($script:Emoji.Times)"
            break
        }
        
        # State 3-pre: Compliant with a pending variable-cert refresh.
        # The two required db certs are present and the device previously
        # reached Event 1808, but Windows Update is now serving the VARIABLE
        # Microsoft Option ROM UEFI CA 2023 cert, producing a fresh 1801. The
        # device is still compliant. Hold Compliant and note the pending cert
        # rather than regressing to Pending. Placed before State 3 so the note
        # is shown even when the servicing registry still reports 'Updated'.
        ($secureBoot -eq 'Enabled' -and $variableCertRefresh) {
            $statusKey     = 'Compliant'
            $cardIconColor = '#26A644'
            $variableShort = $variableDbCertName -replace 'Microsoft ', ''
            $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant <span style="color:#5BC0DE;">(variable cert update pending)</span>'
            $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
            $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Event 1801 (' + $variableShort + ') at ' + $eventTime + ' <span style="color:#5BC0DE;">| prior Event 1808 compliant</span>'
            $detailRowHtml = 'The two required 2023 certificates (Windows UEFI CA 2023 and<br />' +
                             'Microsoft UEFI CA 2023) are present and the device previously<br />' +
                             'reached compliance (Event 1808).<br /><br />' +
                             'Windows Update is now serving the variable ' + $variableShort + '<br />' +
                             'certificate (Event 1801). This does not affect compliance. The<br />' +
                             'variable cert will apply automatically on a following Windows<br />' +
                             'Update cycle (a reboot may be required).'
            $plainText     = "$($script:Emoji.Check) Secure Boot Enabled. Compliant (required 2023 certs + prior 1808). Variable $variableShort update pending (Event 1801)."
            $statusEmoji   = "$($script:Emoji.Check)"
            break
        }
        
        # State 3: Compliant (Secure Boot enabled + Event 1808 found OR UEFICA2023Status == Updated)
        ($secureBoot -eq 'Enabled' -and ($certStatus.Status -eq 'Compliant' -or ($null -ne $servicingStatus -and $servicingStatus.UEFICA2023Status -eq 'Updated'))) {
            $statusKey     = 'Compliant'
            $cardIconColor = '#26A644'
            
            # Check if some certs are still missing (pending reboot to apply)
            $missingDbCerts = @($updatedDbCertNames | Where-Object { $dbCertsFound -notcontains $_ })
            $hasPending1800 = ($null -ne $certStatus -and $certStatus.EventId -eq 1800)
            $certsPendingReboot = ($missingDbCerts.Count -gt 0 -and $hasPending1800)
            
            if ($certsPendingReboot) {
                $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant <span style="color:#F0AD4E;">(reboot pending)</span>'
                $missingShort  = ($missingDbCerts | ForEach-Object { $_ -replace 'Microsoft ', '' -replace 'Windows ', '' }) -join ', '
                $detailRowHtml = "2023 Secure Boot update confirmed by servicing registry.<br />Reboot to apply remaining certs:<br />    $missingShort"
                $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Servicing: Updated <span style="color:#F0AD4E;">| Latest event: 1800 (reboot required)</span>'
                $plainText     = "$($script:Emoji.Check) Secure Boot Enabled. Compliant (UEFICA2023Status=Updated). Reboot pending for $($missingDbCerts.Count) cert(s)."
            }
            elseif ($certStatus.Status -eq 'Compliant') {
                $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant'
                $detailRowHtml = '2023 Secure Boot certificates have been successfully<br />applied to the BIOS firmware.'
                $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
                $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Event 1808 detected at ' + $eventTime
                $plainText     = "$($script:Emoji.Check) Secure Boot Enabled. Certificates up to date in BIOS (Event 1808). Compliant."
            }
            else {
                $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant'
                $detailRowHtml = '2023 Secure Boot certificates have been successfully<br />applied to the BIOS firmware.'
                # Compliant via servicing registry (UEFICA2023Status=Updated) without any SecureBoot events
                $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> No events found. Status confirms compliant.'
                $plainText     = "$($script:Emoji.Check) Secure Boot Enabled. Certificates up to date (UEFICA2023Status=Updated). Compliant."
            }
            $statusEmoji = "$($script:Emoji.Check)"
            break
        }
        
        # State 4: Pending (Secure Boot enabled + Event 1801 found)
        # 1801/1803 indicate certs available but not yet applied - may resolve via WU, or signal OEM blocker
        ($secureBoot -eq 'Enabled' -and $certStatus.Status -eq 'ActionRequired') {
            $statusKey     = 'Pending'
            $cardIconColor = '#F0AD4E'
            $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
            $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
            $latestEventId = if ($certStatus.EventId) { $certStatus.EventId } else { 1801 }
            $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event ' + $latestEventId + ' detected at ' + $eventTime
            
            $oemKeyGuide = Get-OemKeyResetGuide
            $bitlockerNote = '<br /><br />Suspend BitLocker or have recovery keys handy for <br />each enabled volume before resetting keys.'
            
            if ($oemKeyGuide) {
                $guideHtml = '<br /><a href="' + $oemKeyGuide + '" target="_blank">OEM Key Reset Guide</a>'
            }
            else {
                $guideHtml = ''
            }
            
            if ($has2023InDb) {
                # Check if firmware is actively rejecting a write (1795) or signaling OEM blocker (1803) alongside a missing KEK
                $has1795 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1795)
                $has1803 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1803)
                if ($has1795 -and -not $has2023InKek) {
                    # Firmware is rejecting the KEK write - the OEM PK lacks authority to sign/validate
                    # the new Microsoft KEK 2K CA 2023. Without a BIOS update that extends PK trust,
                    # future db additions and dbx revocations will break after KEK 2011 expiration (June).
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $eventRowHtml  = '<i class="fas fa-exclamation-triangle" style="color:#D9534F;"></i> Event 1795 detected at ' + $eventTime
                    $oemBiosGuide = Get-OemBIOSUpdateGuide
                    $biosGuideHtml = if ($oemBiosGuide) { '<br /><a href="' + $oemBiosGuide + '" target="_blank">OEM BIOS/Firmware Update Guide</a>' } else { '' }
                    $dbxRevocationUrl = 'https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/DBX/dbx_info_msft_latest.json'
                    $detailRowHtml = '2023 db certs are present, but the firmware is rejecting<br />' +
                                     'the KEK 2K CA 2023 update (Event 1795).<br /><br />' +
                                     'A BIOS/firmware update from the OEM is required to update<br />' +
                                     'the PK, which signs and validates the KEK 2K CA.<br />' +
                                     'Without it, future updates to both the db (safe list) and the dbx<br />' +
                                     '(<a href="' + $dbxRevocationUrl + '" target="_blank">revocations</a>) ' +
                                     'will break after KEK 2011 expiration (June 2026).' + $biosGuideHtml
                    $plainText     = "$($script:Emoji.Times) Secure Boot Enabled. OEM PK does not authorize/sign KEK 2K CA 2023 (Event 1795). BIOS update required.$(if ($oemBiosGuide) { " Guide: $oemBiosGuide" })"
                    $statusEmoji = "$($script:Emoji.Times)"
                }
                elseif ($has1803 -and -not $has2023InKek) {
                    # Event 1803 = OS could not locate a PK-signed KEK 2023 update to install.
                    # The PK itself is valid; the OEM has simply not yet published a PK-signed
                    # KEK 2023 update to Microsoft for Windows Update to serve. This is a
                    # distribution gap. A user BIOS update will only help if the OEM
                    # bundles the new KEK into that firmware image. The primary
                    # resolution path is OEM publication through WU.
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $eventRowHtml  = '<i class="fas fa-exclamation-triangle" style="color:#D9534F;"></i> Event 1803 detected at ' + $eventTime
                    $dbxRevocationUrl = 'https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/DBX/dbx_info_msft_latest.json'
                    $detailRowHtml = '2023 db certs are present, but KEK 2K CA 2023 is missing<br />' +
                                     'and no PK-signed KEK 2023 update was found via Windows<br />' +
                                     'Update (Event 1803).<br /><br />' +
                                     'This is a service gap separate from a firmware or PK issue:<br />' +
                                     'the OEM has not yet published a PK-signed KEK 2023 update<br />' +
                                     'to Microsoft for WU to serve. Resolution requires the OEM<br />' +
                                     'to ship that KEK update (via WU or bundled in firmware).<br /><br />' +
                                     'Without KEK 2023, future updates to both the db (safe list)<br />' +
                                     'and the dbx (<a href="' + $dbxRevocationUrl + '" target="_blank">revocations</a>) ' +
                                     'will break after<br />KEK 2011 expiration (June 2026).'
                    $plainText     = "$($script:Emoji.Times) Secure Boot Enabled. No PK-signed KEK 2023 available via WU (Event 1803). Awaiting OEM publication through Microsoft."
                    $statusEmoji = "$($script:Emoji.Times)"
                }
                else {
                    $detailRowHtml = '2023 Secure Boot certificates are present in the active<br />database (db), but the OS-side validation is stuck on 1801.<br />Windows Update should* resolve this automatically<br />before the June 2026 enforcement deadline.'
                    $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. 2023 certs in db but OS stuck on 1801. Pending Windows Update validation."
                    $statusEmoji = "$($script:Emoji.Warning)"
                }
            }
            elseif ($has2023InDbDefault) {
                # Check for Event 1803 (PK-signed KEK not available) - the definitive OEM blocker
                $has1803 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1803)
                
                if ($dbIsOsWritable) {
                    # KEK present + UEFI writable - Windows Update will handle it
                    $statusKey     = 'ActionOptional'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />but not yet in the active database (db).<br />Windows is capable of updating the BIOS cert db directly<br />and will eventually push the cert automatically.<br />Optionally, reset Secure Boot keys in BIOS to apply immediately." + $bitlockerNote + $guideHtml
                    $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Pending. Windows Update will apply certs automatically."
                    $statusEmoji = "$($script:Emoji.Warning)"
                }
                elseif ($has1803) {
                    # Event 1803 = OS could not locate a PK-signed KEK 2023 update to install.
                    # The OEM has not yet published a PK-signed KEK update to Microsoft for WU
                    # to serve. 2023 certs are in dbDefault, so a BIOS key reset pulls them in
                    # immediately; otherwise wait on OEM publication.
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#D9534F;"></i> Event 1803 detected at ' + $eventTime
                    $detailRowHtml = "KEK 2K CA 2023 is missing and no PK-signed KEK 2023 update<br />was found via Windows Update (Event 1803).<br />This is a distribution gap: the OEM has not yet published<br />a PK-signed KEK 2023 update to Microsoft for WU to serve.<br />In firmware defaults (dbDefault): $dbDefaultCertLabel<br />Options:<br />• Reset Secure Boot keys in BIOS to apply from defaults<br />• Wait on OEM to publish PK-signed KEK 2023 via WU" + $bitlockerNote + $guideHtml
                    $plainText     = "$($script:Emoji.Times) Secure Boot Enabled. OEM KEK 2023 not available (Event 1803). BIOS update or key reset required."
                    $statusEmoji = "$($script:Emoji.Times)"
                }
                else {
                    # KEK missing but no 1803 - Windows Update may be able to push the KEK
                    # via the 0x4004 bit in AvailableUpdates. Opt-in is the first step.
                    $statusKey     = 'Pending'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />KEK 2K CA 2023 is not yet installed.<br />Windows Update can deliver the PK-signed KEK via opt-in (0x4004 bit)."
                    if ($null -ne $optInStatus -and -not $optInStatus.IsOptedIn) {
                        $detailRowHtml += '<br /><br /><b>Not opted in.</b> Windows will not update CA2023 without opt-in.<br />Set SecureBootAction to &quot;Enable opt-in&quot; to trigger KEK + cert deployment.'
                        $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Not opted in. Pending Opt-In."
                    }
                    else {
                        $detailRowHtml += '<br /><br />Opt-in is enabled. Windows Update will push the KEK<br />and then apply certs. This may take time.'
                        $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Opted in. Pending Windows Update."
                    }
                    $statusEmoji = "$($script:Emoji.Warning)"
                }
            }
            else {
                # 2023 cert not in db OR dbDefault - firmware update or OS-driven update needed
                $has1803 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1803)
                $oemBiosGuide = Get-OemBIOSUpdateGuide
                if ($oemBiosGuide) {
                    $biosGuideHtml = '<br /><a href="' + $oemBiosGuide + '" target="_blank">OEM BIOS/Firmware Update Guide</a>'
                }
                else {
                    $biosGuideHtml = ''
                }
                if ($dbIsOsWritable) {
                    # KEK present + UEFI writable - Windows Update will handle everything
                    $statusKey     = 'ActionOptional'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />However, Windows is capable of updating the BIOS cert db directly.<br />Windows Update will eventually push the cert automatically,<br />or a manual BIOS update can be applied.' + $biosGuideHtml
                    $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. 2023 cert missing; Windows will eventually update the BIOS db directly, or push a BIOS update if available."
                    $statusEmoji = "$($script:Emoji.Warning)"
                }
                elseif ($has1803) {
                    # Event 1803 = OS could not locate a PK-signed KEK 2023 update to install.
                    # With no 2023 cert anywhere (db or dbDefault) AND no PK-signed KEK update
                    # available via WU, resolution requires the OEM to publish a PK-signed KEK
                    # update to Microsoft. A bundled firmware update that ships the new KEK
                    # would also resolve it, but the primary path is WU delivery once the OEM
                    # has published.
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#D9534F;"></i> Event 1803 detected at ' + $eventTime
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />No PK-signed KEK 2023 update was found via Windows<br />Update (Event 1803).<br /><br />This is a distribution gap: the OEM has not yet published<br />a PK-signed KEK 2023 update to Microsoft for WU to serve.<br />Resolution requires OEM publication (via WU or firmware).<br />Expected before June 2026.' + $biosGuideHtml
                    $plainText     = "$($script:Emoji.Times) Secure Boot Enabled. 2023 cert missing; no PK-signed KEK 2023 via WU (Event 1803). Awaiting OEM publication."
                    $statusEmoji = "$($script:Emoji.Times)"
                }
                else {
                    # No cert in db/dbDefault but no 1803 either - opt-in may resolve via Windows Update
                    $statusKey     = 'Pending'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    if ($null -ne $optInStatus -and -not $optInStatus.IsOptedIn) {
                        $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />KEK 2023 is also missing, but no Event 1803 (OEM blocker).<br /><br /><b>Not opted in.</b> Windows will not update CA2023 without opt-in.<br />Set SecureBootAction to &quot;Enable opt-in&quot; to allow WU deployment.' + $biosGuideHtml
                        $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Not opted in. Pending Opt-In."
                    }
                    else {
                        $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />KEK 2023 is also missing, but no Event 1803 (OEM blocker).<br />Opt-in is enabled - Windows Update may deliver KEK + certs.<br />If no progress, a BIOS update may be needed.' + $biosGuideHtml
                        $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Opted in. Pending Windows Update."
                    }
                    $statusEmoji = "$($script:Emoji.Warning)"
                }
            }
            break
        }
        
        # State 5a: Pending Cert Reboot (Event 1800 - reboot required to continue)
        ($secureBoot -eq 'Enabled' -and $certStatus.EventId -eq 1800 -and -not $postTriggerState) {
            $statusKey     = 'Pending'
            $cardIconColor = '#F0AD4E'
            $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending Cert Reboot'
            $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
            $eventRowHtml  = '<i class="fas fa-redo" style="color:#F0AD4E;"></i> Event 1800 detected at ' + $eventTime
            $detailRowHtml = 'Secure Boot certificate update is in progress.<br />A system reboot is required to continue the update.<br />Reboot the machine to allow the update to proceed.'
            $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Reboot required to continue certificate update (Event 1800)."
            $statusEmoji   = "$($script:Emoji.Warning)"
            $rebootStatus  = Get-PendingRebootStatus
            if ($rebootStatus.Pending) {
                $sourceList = $rebootStatus.Sources -join ', '
                $detailRowHtml += '<br /><br />Reboot pending from: ' + $sourceList
            }
            if ($enforceMissingOptIn) {
                $detailRowHtml += '<br /><br /><span style="color:#F59E0B;"><i class="fas fa-exclamation-triangle" style="color:#F59E0B;"></i> SVN Enforcement is active but WU opt-in is not enabled.<br />Set securebootAction to &quot;Enable opt-in&quot; for full deployment.</span>'
                $plainText     += " $($script:Emoji.Warning) SVN Enforcement active but WU opt-in not enabled."
            }
            break
        }
        
        # State 5b-pre-blocker: All mitigations applied AND a PK-blocks-KEK signal is firing
        # ($pkBlockingKek is set when Event 1795 is firing and KEK 2K CA 2023 is missing on a
        # legitimate OEM PK). This must come BEFORE the "All mitigations applied -> Compliant
        # (pending 1808)" path below: that path treats 1799+1037+1042+has2023InDb as
        # sufficient for green, but on a PK-blocked device those mitigation events firing
        # doesn't change the fact that the OEM PK can't authorize the next KEK and Windows
        # Update is actively bouncing 1795 errors. After KEK 2011 expires (June 2026) no
        # further db/dbx updates will land - this is genuinely Action Required, not Compliant.
        # Renders the same OEM-BIOS narrative used by the State 5 1795 branch so operators
        # see one consistent story regardless of which event happens to be the "most recent".
        ($secureBoot -eq 'Enabled' -and $certStatus.Status -eq 'Pending' -and -not $postTriggerState -and
         $has2023InDb -and $pkBlockingKek -and
         (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1799) -and
         (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1037) -and
         (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1042)) {
            $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
            $statusKey     = 'ActionRequired'
            $cardIconColor = '#D9534F'
            $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
            $eventRowHtml  = '<i class="fas fa-exclamation-triangle" style="color:#D9534F;"></i> Event 1795 detected (firmware rejecting KEK 2023 write)'
            $oemBiosGuide  = Get-OemBIOSUpdateGuide
            $biosGuideHtml = if ($oemBiosGuide) { '<br /><a href="' + $oemBiosGuide + '" target="_blank">OEM BIOS/Firmware Update Guide</a>' } else { '' }
            $dbxRevocationUrl = 'https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/DBX/dbx_info_msft_latest.json'
            $detailRowHtml = 'All four mitigations have applied (db cert, 2023 boot mgr,<br />' +
                             '2011 CA revocation, SVN bump), but the firmware is<br />' +
                             'rejecting the KEK 2K CA 2023 update (Event 1795).<br /><br />' +
                             'The OEM PK does not carry the authority chain to sign or<br />' +
                             'validate the new Microsoft KEK 2K CA 2023, so Windows<br />' +
                             'Update cannot push the KEK. A BIOS/firmware update from<br />' +
                             'the OEM is required to extend PK trust.<br /><br />' +
                             'Without it, future updates to both the db (safe list)<br />' +
                             'and the dbx (<a href="' + $dbxRevocationUrl + '" target="_blank">revocations</a>) ' +
                             'will break after<br />KEK 2011 expiration (June 2026).' + $biosGuideHtml
            $plainText     = "$($script:Emoji.Times) Secure Boot Enabled. Mitigations applied but OEM PK does not authorize KEK 2K CA 2023 (Event 1795). BIOS update required.$(if ($oemBiosGuide) { " Guide: $oemBiosGuide" })"
            $statusEmoji   = "$($script:Emoji.Times)"
            break
        }
        
        # State 5b-pre: All mitigations applied (1037+1042+1799 present), awaiting final 1808
        # This device has completed all stages but 1808 hasn't fired yet (needs scheduled task run post-reboot).
        ($secureBoot -eq 'Enabled' -and $certStatus.Status -eq 'Pending' -and -not $postTriggerState -and
         $has2023InDb -and
         (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1799) -and
         (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1037) -and
         (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1042)) {
            $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
            $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Event ' + $certStatus.EventId + ' detected at ' + $eventTime
            $statusKey     = 'Compliant'
            $cardIconColor = '#26A644'
            $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant <span style="color:#F0AD4E;">(pending 1808)</span>'
            $detailRowHtml = 'All mitigations have been applied:<br /><i class="fas fa-check-circle" style="color:#26A644;"></i> 2023 cert in db (Stage 1)<br /><i class="fas fa-check-circle" style="color:#26A644;"></i> 2023 boot manager installed (Event 1799)<br /><i class="fas fa-check-circle" style="color:#26A644;"></i> PCA 2011 revoked in DBX (Event 1037)<br /><i class="fas fa-check-circle" style="color:#26A644;"></i> SVN applied to DBX (Event 1042)<br /><br />Awaiting Event 1808 confirmation from OS'
            $plainText     = "$($script:Emoji.Check) Secure Boot Enabled. All mitigations applied. Awaiting 1808 confirmation."
            $statusEmoji   = "$($script:Emoji.Check)"
            break
        }
        
        # State 5b: Pending (Secure Boot enabled, no state events or only non-state events)
        # Sub-branches based on whether 2023 cert exists in db or dbDefault
        ($secureBoot -eq 'Enabled' -and $certStatus.Status -eq 'Pending' -and -not $postTriggerState) {
            # Check if there are meaningful deployment events (1799/1800/1037/1042) vs truly no events
            $hasDeploymentEvents = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1799) -or
                                   (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1800) -or
                                   (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1037) -or
                                   (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1042)
            $eventTime = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
            
            if ($hasDeploymentEvents) {
                $eventRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Event ' + $certStatus.EventId + ' detected at ' + $eventTime
            }
            else {
                $eventRowHtml = '<i class="fas fa-search" style="color:#F0AD4E;"></i> No certificate update events (1808/1801) found'
            }
            
            if ($has2023InDb) {
                if ($hasDeploymentEvents) {
                    # Has cert + deployment events - mitigations in progress, just not all 3 completion events yet
                    $statusKey     = 'Pending'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $detailRowHtml = 'Secure Boot certificate update is in progress.<br />2023 cert is present in db. Deployment events logged.<br />Awaiting remaining mitigations to complete.'
                    $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Update in progress. Awaiting remaining mitigations."
                }
                else {
                    # Has cert but no deployment events at all - possibly pre-installed by firmware
                    $statusKey     = 'Pending'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $detailRowHtml = '2023 Secure Boot certificate is present in the active db<br />but no completion events (1808/1801) were logged.<br />Cert may have been pre-installed by firmware.<br />Awaiting Windows Update to finalize validation.'
                    $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. 2023 cert in db but no events logged. Waiting for Windows Update to finalize."
                }
            }
            elseif ($has2023InDbDefault) {
                # 2023 cert in firmware defaults but not deployed - Windows Update or key reset can resolve
                $oemKeyGuide = Get-OemKeyResetGuide
                $bitlockerNote = '<br /><br />Suspend BitLocker or have recovery keys handy for <br />each enabled volume before resetting keys.'
                if ($oemKeyGuide) {
                    $guideHtml = '<br /><a href="' + $oemKeyGuide + '" target="_blank">OEM Key Reset Guide</a>'
                }
                else {
                    $guideHtml = ''
                }
                $cardIconColor = '#F0AD4E'
                # Check for Event 1803 (PK-signed KEK not available)
                $has1803 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1803)
                
                if ($dbIsOsWritable) {
                    $statusKey     = 'ActionOptional'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />Not yet in the active database (db).<br />Windows is capable of updating the BIOS cert db directly<br />and will eventually push the cert automatically.<br />Optionally, reset Secure Boot keys in BIOS to apply immediately." + $bitlockerNote + $guideHtml
                    $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Pending. Windows Update will apply certs automatically."
                    $eventRowHtml  = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> No events - Windows capable of updating BIOS db'
                }
                elseif ($has1803) {
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $detailRowHtml = "KEK 2K CA 2023 not available - OEM has not provided a<br />PK-signed KEK update (Event 1803).<br />In firmware defaults (dbDefault): $dbDefaultCertLabel<br />Options:<br />• Wait for OEM firmware update that includes KEK 2023<br />• Reset Secure Boot keys in BIOS to apply from defaults" + $bitlockerNote + $guideHtml
                    $plainText     = "$($script:Emoji.Times) Secure Boot Enabled. OEM KEK 2023 not available (Event 1803). BIOS update or key reset required."
                    $eventRowHtml  = '<i class="fas fa-exclamation-circle" style="color:#D9534F;"></i> Event 1803 - OEM KEK blocker'
                    $statusEmoji = "$($script:Emoji.Times)"
                }
                else {
                    # KEK missing but no 1803 - opt-in can push KEK
                    $statusKey     = 'Pending'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />KEK 2K CA 2023 is not yet installed.<br />Windows Update can deliver the PK-signed KEK via opt-in."
                    if ($null -ne $optInStatus -and -not $optInStatus.IsOptedIn) {
                        $detailRowHtml += '<br /><br /><b>Not opted in.</b> Windows will not update CA2023 without opt-in.<br />Set SecureBootAction to &quot;Enable opt-in&quot; to trigger KEK + cert deployment.'
                        $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Not opted in. Pending Opt-In."
                    }
                    else {
                        $detailRowHtml += '<br /><br />Opt-in is enabled. Windows Update will push the KEK<br />and then apply certs. This may take time.'
                        $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Opted in. Pending Windows Update."
                    }
                    $eventRowHtml  = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> No events - KEK pending via Windows Update'
                }
            }
            else {
                # 2023 cert not in db OR dbDefault - firmware update or OS-driven update needed
                $oemBiosUpdateGuide = Get-OemBIOSUpdateGuide
                if ($oemBiosUpdateGuide) {
                    $guideHtml = '<br /><a href="' + $oemBiosUpdateGuide + '" target="_blank">OEM BIOS/Firmware Update Guide</a>'
                }
                else {
                    $guideHtml = ''
                }
                if ($dbIsOsWritable) {
                    $statusKey     = 'ActionOptional'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />However, Windows is capable of updating the BIOS cert db directly.<br />Windows Update may push the cert automatically,<br />or a manual BIOS update can be applied.' + $guideHtml
                    $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. 2023 cert missing; Windows can update BIOS db directly, or push BIOS update."
                    $eventRowHtml  = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> No events - Windows capable of updating BIOS db'
                    $statusEmoji = "$($script:Emoji.Warning)"
                }
                else {
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />A BIOS/firmware update from the OEM is required<br />to add 2023 certificate support before Windows Update<br />can complete the rotation. Update before June 2026.' + $guideHtml
                    $plainText     = "$($script:Emoji.Times) Secure Boot Enabled. 2023 cert missing from db and dbDefault. OEM BIOS/firmware update required."
                    $eventRowHtml  = '<i class="fas fa-exclamation-circle" style="color:#D9534F;"></i> No events - BIOS lacks 2023 certificate support'
                    $statusEmoji = "$($script:Emoji.Times)"
                }
            }
            break
        }
        
        # Fallback: unexpected state combination
        default {
            $statusKey     = 'Unknown'
            $cardIconColor = '#6C757D'
            $statusRowHtml = '<i class="fas fa-question-circle" style="color:#6C757D;"></i> Unknown'
            $detailRowHtml = 'An unexpected state was encountered. Review script output for details.'
            $plainText     = "$($script:Emoji.QuestionWhite) Secure Boot certificate status could not be determined."
            $statusEmoji = "$($script:Emoji.QuestionWhite)"
        }
    }
    
    # Override for triggered OS update based on post-trigger state
    # Servicing registry is re-checked after trigger - if it says Updated, that's definitive.
    # NOTE: $eventRowHtml is never overridden here - the newest-event logic (below) resolves
    # the actual last event from the log, regardless of post-trigger state.
    if ($postTriggerState) {
        switch ($postTriggerState) {
            'Compliant' {
                # Servicing confirmed Updated, or 1808 appeared
                $statusKey     = 'Compliant'
                $cardIconColor = '#26A644'
                $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant'
                $detailRowHtml = 'Triggered OS-side update.<br />2023 certificates successfully applied to BIOS firmware.'
                $plainText     = "$($script:Emoji.Check) Secure Boot Enabled. Triggered OS update; confirmed compliant. Certificates up to date."
                $statusEmoji = "$($script:Emoji.Check)"
            }
            'Pending1808' {
                # 1799 found - update is in progress
                $statusKey     = 'Pending'
                $cardIconColor = '#F0AD4E'
                $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                $detailRowHtml = 'Triggered OS-side update.<br />Boot manager installed (Event 1799).<br />Update in progress - servicing will confirm when complete.'
                $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Triggered OS update; boot manager installed. Update in progress."
                $statusEmoji = "$($script:Emoji.Warning)"
            }
            default {
                # No events yet - update may need a reboot to proceed
                $rebootStatus = Get-PendingRebootStatus
                $statusKey     = 'Pending'
                $cardIconColor = '#F0AD4E'
                $statusEmoji = "$($script:Emoji.Warning)"
                if ($rebootStatus.Pending) {
                    $sourceList = $rebootStatus.Sources -join ', '
                    Write-Log "INFO" "Reboot pending from: $sourceList"
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending Cert Reboot'
                    $detailRowHtml = 'Triggered OS-side update.<br />A system reboot is pending (' + $sourceList + ').<br />Reboot may be required before update can proceed.'
                    $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Triggered OS update; reboot pending (" + $sourceList + ').'
                }
                else {
                    Write-Log "INFO" "No pending reboot detected; update may still be processing"
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $detailRowHtml = 'Triggered OS-side update.<br />Update is processing - servicing will confirm when complete.'
                    $plainText     = "$($script:Emoji.Warning) Secure Boot Enabled. Triggered OS update; processing."
                }
            }
        }
    }
    
    Write-Log "INFO" "Resolved final state: $statusKey"
    
    # Append SVN context to detail text when SVN data is available
    # This gives a quick rundown of SVN status alongside the cert-focused detail
    if ($null -ne $svnStatus) {
        $svnPendingUpdate = ($null -ne $svnStatus.PendingUpdate -and $svnStatus.PendingUpdate)
        $svnNotApplied    = ($null -ne $svnStatus.SvnNotApplied -and $svnStatus.SvnNotApplied)
        $svnRebootNeeded = ($svnStatus.RebootPending -or $svnStatus.RevocationAppliedPendingReboot -or $svnPendingUpdate -or $svnNotApplied)
        # Title suffix precedence, most-specific first:
        #   1. SvnNotApplied  -> firmware already booted since the last DBX write
        #      (Event 1034/1042 predates lastBootTime) and still refused to absorb.
        #      RED suffix "(SVN Update Not Applied: X)" - surfaces the OEM/BIOS
        #      escalation signal at the top of the card so operators don't keep
        #      rebooting a stuck device.
        #   2. PendingUpdate  -> firmware at prior SVN, reboot hasn't happened yet
        #      since the DBX write. AMBER suffix "(Pending SVN Update: X)". Benign.
        #   3. Generic RebootNeeded -> fallback for 3-of-3 missing or revocation-
        #      reboot or cmdlet-path RebootPending without component detail.
        # All three are reliably distinguishable thanks to the raw-DBX max-SVN fix
        # (see Get-DbxBootMgrSVN / https://github.com/PowerShell/PowerShell/issues/27058).
        if ($svnNotApplied) {
            $compList = @($svnStatus.SvnNotAppliedComponents) -join ', '
            $compSafe = [System.Net.WebUtility]::HtmlEncode($compList)
            $statusRowHtml += ' <span style="color:#D9534F; font-size:0.85em;">(SVN Update Not Applied: ' + $compSafe + ')</span>'
            if ($plainText -notmatch 'SVN') {
                $plainText += " SVN update not applied ($compList), firmware did not absorb after reboot."
            }
        }
        elseif ($svnPendingUpdate) {
            $compList = @($svnStatus.PendingUpdateComponents) -join ', '
            $compSafe = [System.Net.WebUtility]::HtmlEncode($compList)
            $statusRowHtml += ' <span style="color:#F59E0B; font-size:0.85em;">(Pending SVN Update: ' + $compSafe + ')</span>'
            if ($plainText -notmatch 'SVN') {
                $plainText += " Pending SVN update ($compList)."
            }
        }
        elseif ($svnRebootNeeded) {
            $statusRowHtml += ' <span style="color:#F59E0B; font-size:0.85em;">(Pending SVN Reboot)</span>'
            if ($plainText -notmatch 'SVN') {
                $plainText += ' Pending SVN reboot.'
            }
        }
        # Append SVN summary, so the SVN line is the single source of action status for both certs and SVN
        $svnSummary = if ($svnNotApplied) {
            'Firmware refused to apply SVN update after reboot.<br />OEM BIOS/firmware update or escalation may be required <br />if this does not resolve on it''s own.'
        }
        elseif ($svnRebootNeeded) {
            'Reboot required to complete SVN updates.'
        }
        elseif ($svnStatus.IsCompliant) {
            'No action required.'
        }
        elseif ($statusKey -eq 'Compliant' -and ($svnStatus.RevocationPending -or $svnStatus.SvnUpdatePending)) {
            # Cert rotation complete - SVN stages 3+4 are future enforcement and not a pending action
            $null
        }
        elseif ($svnStatus.RevocationPending -or $svnStatus.SvnUpdatePending) {
            'SVN updates pending. Awaiting Microsoft rollout (June 2026 - 2027).'
        }
        else {
            'SVN update in progress.'
        }
        if ($svnSummary) { $detailRowHtml += "<br />$svnSummary" }
        # Keep $statusEmoji unchanged. Cert compliance is still valid, SVN info is supplemental
    }
    
    # Append the current SVN stage to the plaintext SecureBootStatus field so operators
    # reading the single-line field can see "Stage N" without opening the card.
    # Suppress only when:
    #   (a) Secure Boot is Disabled / NotApplicable / Unknown / Virtualized (stage is meaningless)
    #   (b) Device is truly done: $statusKey = 'Compliant' AND no SVN reboot pending AND
    #       $svnStatus.IsCompliant (firmware SVN == staged SVN). The "Compliant (Pending SVN Reboot)"
    #       variant leaves $statusKey = 'Compliant' while the device still has work - stage is still
    #       relevant there, so the old $statusKey-only check was over-suppressing.
    # Also skip when the line already references a stage.
    $trulyDone = ($statusKey -eq 'Compliant') -and
                 (-not $svnRebootNeeded) -and
                 ($null -ne $svnStatus -and $svnStatus.IsCompliant)
    $suppressStage = $trulyDone -or
                     ($statusKey -in @('Disabled', 'NotApplicable', 'Unknown', 'Virtualized', 'PKUntrusted')) -or
                     ($secureBoot -ne 'Enabled')
    if (-not $suppressStage -and $null -ne $svnStatus -and -not [string]::IsNullOrWhiteSpace($svnStatus.Stage)) {
        if ($plainText -notmatch '(?i)\bstage\b') {
            $plainText = "$plainText | $($svnStatus.Stage)"
        }
    }
    
    # Update "Last Event" if a newer event exists beyond the cert-state event (e.g. 1037, 1042)
    # The state machine picks the latest STATE event (1799/1800/1801/1808) for cert compliance,
    # but 1037/1042 may be more recent and should be reflected as the actual last event.
    # Also fires when $eventRowHtml is null (e.g. post-trigger default path doesn't set it).
    if ($null -ne $certStatus -and $null -ne $certStatus.AllEvents -and $certStatus.AllEvents.Count -gt 0) {
        $newestEvent = $certStatus.AllEvents | Sort-Object Time -Descending | Select-Object -First 1
        if ($null -ne $newestEvent -and ($null -eq $eventRowHtml -or ($null -ne $certStatus.EventTime -and $newestEvent.Time -gt $certStatus.EventTime))) {
            $newestTimeStr = $newestEvent.Time.ToString('yyyy-MM-dd HH:mm')
            $newestDesc = $newestEvent.Description
            $newestColor = switch ($newestEvent.Id) {
                1037  { '#26A644' }
                1042  { '#26A644' }
                1808  { '#26A644' }
                1799  { '#26A644' }
                1800  { '#F0AD4E' }
                1801  { '#F0AD4E' }
                { $_ -in @(1032, 1033, 1795, 1796, 1797, 1798, 1802, 1803) } { '#D9534F' }
                default { '#5BC0DE' }
            }
            $newestIcon = if ($newestColor -eq '#D9534F') { 'fa-exclamation-triangle' }
                          elseif ($newestColor -eq '#F0AD4E') { 'fa-clock' }
                          else { 'fa-calendar-check' }
            $eventRowHtml = "<i class='fas $newestIcon' style='color:$newestColor;'></i> Event $($newestEvent.Id) at $newestTimeStr"
        }
    }
    
    # -----------------------------------------------
    # Step 4: Build the HTML status card
    # -----------------------------------------------
    $cardProperties = [ordered]@{
        'Secure Boot' = $statusRowHtml
        'Detail'      = $detailRowHtml
    }
    if ($null -ne $eventRowHtml) {
        $cardProperties['Last Event'] = $eventRowHtml
    }
    # Event log summary (deployment timeline)
    if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus -and $certStatus.EventSummary.Count -gt 0) {
        $cardProperties['Event Log'] = Build-EventLogSection -Format 'Html'
    }
    # Pre-compute which certs are "unconfirmed", OS hasn't confirmed via 1799/1808.
    # A cert is unconfirmed when: its manifest bit is set AND neither 1799 nor 1808 is the current state event.
    # 1799 = boot manager installed (certs applied, progressing), 1808 = fully confirmed.
    $certsUnconfirmed = @()
    $osConfirmed = ($null -ne $certStatus -and $certStatus.EventId -in @(1799, 1808))
    if ($secureBoot -eq 'Enabled' -and -not $osConfirmed -and $null -ne $optInStatus -and $optInStatus.EffectiveAvailable -ne 0) {
        $preAvVal = $optInStatus.EffectiveAvailable
        if ($preAvVal -band 0x0040)  { $certsUnconfirmed += 'Windows UEFI CA 2023' }
        if ($preAvVal -band 0x0800)  { $certsUnconfirmed += 'Option ROM UEFI CA 2023' }
        if ($preAvVal -band 0x1000)  { $certsUnconfirmed += 'UEFI CA 2023' }
        # KEK: test bit 0x0004 specifically - 0x4000 is the conditional qualifier (not the KEK bit)
        if ($preAvVal -band 0x0004)  { $certsUnconfirmed += 'KEK 2K CA 2023' }
    }
    # Post-compliance variable-cert refresh: render the Option ROM row as
    # pending (blue) rather than missing (red X). Build-CertInventorySection
    # matches the full cert name, so add the full name here.
    if ($variableCertRefresh -and ($certsUnconfirmed -notcontains $variableDbCertName)) {
        $certsUnconfirmed += $variableDbCertName
    }
    
    # ($pkBlockingKek is computed earlier, before the state-resolution switch, so the
    # State 5b-pre-blocker case at the top of the switch can consult it. See the
    # block above the switch for the full rationale.)
    
    # Certificate inventory (all four 2023 certs - only when Secure Boot is Enabled)
    if ($secureBoot -eq 'Enabled') {
        $cardProperties['Certificates'] = Build-CertInventorySection -Format 'Html'
    }
    # PK Security Alert (PKFail / CVE-2024-8105) - detailed remediation narrative when PK is untrusted.
    # Placed right after Certificates so the red PK inventory row and the alert section sit together.
    # Delegated to Build-PkSecurityAlertSection so the Html (Ninja) and Local outputs share one source of truth.
    if ($statusKey -eq 'PKUntrusted') {
        $cardProperties['PK Security Alert'] = Build-PkSecurityAlertSection -Format 'Html'
    }
    # Factory defaults - only surface when something is missing (healthy devices get no row)
    if ($secureBoot -eq 'Enabled' -and ($defaultsAllMissing -or $defaultsSomeMissing)) {
        $cardProperties['Factory Defaults'] = Build-FactoryDefaultsSection -Format 'Html'
    }
    # HP BIOS CA 2023 interface (only HP devices where WMI was readable)
    if ($isHpManufacturer -and $null -ne $hpBios -and $hpBios.Available) {
        $hpContent = Build-HpBiosSection -Format 'Html' -HpBios $hpBios -StuckPattern $hpStuckPattern -Remediation $hpRemediation
        if ($null -ne $hpContent) { $cardProperties['HP BIOS CA 2023'] = $hpContent }
    }
    # Servicing status (only when Secure Boot is Enabled and servicing data exists)
    if ($secureBoot -eq 'Enabled' -and $null -ne $servicingStatus) {
        $servContent = Build-ServicingSection -Format 'Html'
        if ($null -ne $servContent) { $cardProperties['Servicing'] = $servContent }
    }
    # AvailableUpdates bitmask decoded. Shown when registry has a value OR event-confirmed mitigations exist
    # Cross-reference manifest bits against actual cert inventory to determine what's truly applied
    $has1037ForManifest = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1037)
    $has1042ForManifest = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1042)
    $hasEventMitigations = $has1037ForManifest -or $has1042ForManifest
    $hasRegistryManifest = ($null -ne $optInStatus -and $optInStatus.EffectiveAvailable -ne 0)
    if ($secureBoot -eq 'Enabled' -and ($hasRegistryManifest -or $hasEventMitigations)) {
        # Re-read AvailableUpdates fresh. Windows may have updated the registry with mitigation bits
        # (0x0080 = Mitigation 3, 0x0200 = Mitigation 4) since Check-OptInStatus ran in Step 2.3
        $freshAvailable = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty 'AvailableUpdates' -ErrorAction SilentlyContinue)
        if ($null -eq $freshAvailable) { $freshAvailable = 0 }
        $avVal = if ($null -ne $optInStatus -and $optInStatus.AvailableUpdatesPolicySet) { $optInStatus.AvailableUpdatesPolicy } else { $freshAvailable }
        
        # Enrich with event-confirmed mitigations whose bits may not be in the registry
        if ($has1037ForManifest -and -not ($avVal -band 0x0080)) { $avVal = $avVal -bor 0x0080 }
        if ($has1042ForManifest -and -not ($avVal -band 0x0200)) { $avVal = $avVal -bor 0x0200 }
        
        $avHex  = '0x{0:X}' -f $avVal
        $source = if ($null -ne $optInStatus -and $optInStatus.AvailableUpdatesPolicySet) { 'Policy' }
                  elseif ($freshAvailable -ne 0) { 'Registry' }
                  else { 'Events' }
        # Re-decode with enriched value so bullet points include mitigations
        $enrichedMeaning = Get-AvailableUpdatesMeaning -Value $avVal
        
        # Check each manifest bit against actual cert presence
        $manifestPending = @()
        if (($avVal -band 0x0004) -or ($avVal -band 0x4004)) {
            if (-not $has2023InKek) { $manifestPending += 'KEK 2K CA 2023' }
        }
        if ($avVal -band 0x0040) {
            if ($dbCertsFound -notcontains 'Windows UEFI CA 2023') { $manifestPending += 'Windows UEFI CA 2023' }
        }
        if ($avVal -band 0x0800) {
            if ($dbCertsFound -notcontains 'Microsoft Option ROM UEFI CA 2023') { $manifestPending += 'Option ROM UEFI CA 2023' }
        }
        if ($avVal -band 0x1000) {
            if ($dbCertsFound -notcontains 'Microsoft UEFI CA 2023') { $manifestPending += 'Microsoft UEFI CA 2023' }
        }
        # Boot manager bit (0x0100) - if 1799 has occurred, boot manager is installed
        if ($avVal -band 0x0100) {
            $has1799 = ($null -ne $certStatus -and $certStatus.EventId -eq 1799) -or
                       (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1799)
            if (-not $has1799) { $manifestPending += 'Boot manager (2023-signed)' }
        }
        # Mitigation 3 (0x80) - Revoke PCA 2011 in DBX; complete when 2011 CA appears in dbx or Event 1037 fires
        if ($avVal -band 0x0080) {
            $has1037 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1037)
            if ($ca2011RevokedInDbx.Count -eq 0 -and -not $has1037) { $manifestPending += 'PCA 2011 revocation (Mitigation 3)' }
        }
        # Mitigation 4 (0x200) - Apply SVN to DBX firmware; complete when SVN appears in DBX or Event 1042 fires
        if ($avVal -band 0x0200) {
            $has1042 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1042)
            $dbxSvnPresent = ($null -ne $svnStatus -and $null -ne $svnStatus.DbxSVN)
            if (-not $dbxSvnPresent -and -not $has1042) { $manifestPending += 'SVN update (Mitigation 4)' }
        }
        
        $allApplied = ($manifestPending.Count -eq 0)
        $pendingReboot = ($null -ne $certStatus -and $certStatus.EventId -eq 1800)
        
        # Only show SVN reboot in Updates section when mitigations are still pending reboot to write to DBX
        # (RevocationAppliedPendingReboot = 1037 fired but not visible in DBX yet)
        # NOT when firmware SVN just needs to absorb, that is shown in SVN Compliance section
        $svnRebootForManifest = ($null -ne $svnStatus -and $svnStatus.RevocationAppliedPendingReboot)
        # Log the registry data to console (not shown on card)
        Write-Log "INFO" "Update Manifest: $avHex ($source) | Enriched meaning: $($enrichedMeaning -join '; ')"
        $cardProperties['Updates'] = Build-UpdatesSection -Format 'Html'
    }
    elseif ($secureBoot -eq 'Enabled') {
        # No manifest data and no event-confirmed mitigations - still show the section
        $chk = '<i class="fas fa-check-circle" style="color:#26A644;"></i>'
        $cardProperties['Updates'] = "$chk No Updates Pending <span style='color:#26A644;'>(all applied)</span>"
    }
    # SVN Compliance (Get-SecureBootSVN cmdlet or raw DBX byte fallback)
    $svnWhatIsThis = '<a href="https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d" target="_blank" rel="nofollow noopener noreferrer" style="font-size:0.75em;">What is this <i class="fas fa-question-circle" style="color:#6B7280;"></i></a>'
    $svnSectionTitle = "SVN Compliance $svnWhatIsThis"
    if ($secureBoot -eq 'Enabled' -and $null -ne $svnStatus) {
        $cardProperties[$svnSectionTitle] = Build-SvnComplianceSection -Format 'Html'
    }
    if ($null -ne $svnBitLockerSafetyResult) {
        $svnBitLockerContent = Build-SvnBitLockerSection -Format 'Html' -Result $svnBitLockerSafetyResult
        if ($null -ne $svnBitLockerContent) {
            $cardProperties['SVN BitLocker Safety'] = $svnBitLockerContent
        }
    }
    
    # Boot media check: runs regardless of state to catch outdated 2011-signed bootable USB/CD
    # attached to the device. Only emits a card section when outdated media is detected.
    # Result cached in $bootMediaResult so the Html + Local paths share one scan + rendering.
    $bootMediaResult = $null
    try {
        $bootMediaResult = Test-BootMediaPca2023 -DeepScan:$DeepBootMediaScan
        if ($null -ne $bootMediaResult -and $bootMediaResult.Outdated.Count -gt 0) {
            # Surface on plaintext SecureBootStatus field + activity log (must run exactly once)
            $outdatedCount = $bootMediaResult.Outdated.Count
            $plainText += " [!] $outdatedCount outdated boot file(s) on attached media."
            Write-Log "WARNING" "Outdated boot media detected on $($bootMediaResult.MediaScanned) volume(s): $outdatedCount file(s) PCA-2011-signed"
        }
    }
    catch {
        Write-Log "INFO" "Boot media scan failed: $($_.Exception.Message)"
    }
    if ($null -ne $bootMediaResult -and $bootMediaResult.Outdated.Count -gt 0) {
        $cardProperties['Boot Media'] = Build-BootMediaSection -Format 'Html' -Result $bootMediaResult
    }
    
    # KEK Update Availability: when KEK 2023 is missing AND the firmware is actively rejecting
    # writes (Event 1795) or missing PK-signed KEK (Event 1803), check if Microsoft publishes
    # a vendor-signed KEK update for this PK. This guides the Action Required messaging.
    # Result cached in $kekLookupResult so the Html + Local paths share one lookup + rendering.
    $kekLookupResult = $null
    $kekNeedsLookup = ($secureBoot -eq 'Enabled' -and -not $has2023InKek -and
                       ((Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1795) -or
                        (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1803)))
    if ($kekNeedsLookup -and $pkCerts.Count -gt 0) {
        $pkThumbprint = $null
        foreach ($pkc in $pkCerts) {
            if ($pkc.PSObject.Properties['Thumbprint'] -and -not [string]::IsNullOrWhiteSpace([string]$pkc.Thumbprint)) {
                $pkThumbprint = [string]$pkc.Thumbprint
                break
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($pkThumbprint)) {
            Write-Log "INFO" "Looking up KEK 2023 update availability for PK thumbprint $pkThumbprint"
            $kekLookupResult = Get-KekUpdateAvailability -PkThumbprint $pkThumbprint
            if ($kekLookupResult.Succeeded -and $kekLookupResult.Available) {
                Write-Log "INFO" "KEK 2023 vendor update available ($($kekLookupResult.Vendors -join ', '))"
            }
            elseif (-not $kekLookupResult.Succeeded) {
                Write-Log "INFO" "KEK update lookup skipped: $($kekLookupResult.Error)"
            }
        }
    }
    if ($null -ne $kekLookupResult -and $kekLookupResult.Succeeded -and $kekLookupResult.Available) {
        $cardProperties['KEK Update Available'] = Build-KekUpdateAvailabilitySection -Format 'Html' -Result $kekLookupResult
    }
    
    # DBX Validation: cross-reference firmware DBX against DBX .bin update files staged by
    # Windows servicing (C:\Windows\System32\SecureBootUpdates\). Answers the actionable
    # question "did the Secure-Boot-Update scheduled task successfully commit what servicing
    # staged?" - no network call, no aspirational compare. Runs whenever Secure Boot is
    # Enabled and DBX bytes are available; staged .bin presence is what determines if the
    # check produces output (absent files -> Succeeded=$false, silently skipped).
    # Result cached in $dbxValidationResult so Html + Local share one comparison + rendering.
    # The early pass (near $svnStatus decoration) may have already populated this to
    # feed the top-level "Pending SVN Update" classification - reuse it when present.
    if ($null -eq $dbxValidationResult -and $secureBoot -eq 'Enabled' -and $null -ne $dbxBytes) {
        $dbxValidationResult = Compare-DbxAgainstStagedBins -DbxBytes $dbxBytes
    }
    if ($null -ne $dbxValidationResult) {
        Write-Log "INFO" "Running DBX validation against staged updates in C:\Windows\System32\SecureBootUpdates"
        if ($dbxValidationResult.Succeeded) {
            Write-Log "INFO" "DBX validation: $($dbxValidationResult.MatchedCount) matched, $($dbxValidationResult.MissingCount) missing, $($dbxValidationResult.SupersededCount) superseded of $($dbxValidationResult.RequiredCount) staged (across $($dbxValidationResult.FilesScanned) file(s))"
            $mc = @($dbxValidationResult.MissingComponents)
            if ($mc.Count -gt 0) {
                # Classify the miss pattern for log severity and wording. Five cases,
                # mirroring Build-SvnComplianceSection's card-side branch logic:
                #   1. All 3 missing + every firmware SVN null  -> pre-rollout (Stage 1/2),
                #      Microsoft hasn't pushed the revocation yet. INFO, reassuring.
                #   2. All 3 missing + at least one firmware SVN populated -> pre-reboot
                #      (Stage 3/4 with fresh staged cumulative). INFO, pending reboot.
                #   3. 1-2 missing + every missing has prior SVN + firmware had NO chance
                #      (lastBootTime < latest(1034,1042)) -> benign pending SVN update,
                #      reboot will apply. INFO.
                #   4. 1-2 missing + every missing has prior SVN + firmware HAD a chance
                #      (lastBootTime > latest(1034,1042)) -> firmware refused to absorb
                #      after reboot. WARNING - operators need to know reboot won't fix it.
                #      Uses $svnStatus.SvnNotApplied as the authoritative signal.
                #   5. 1-2 missing + at least one has NO firmware SVN -> true partial
                #      firmware commit, component-asymmetric rejection. WARNING.
                $descLines = foreach ($m in $mc) {
                    $r = if ([string]::IsNullOrWhiteSpace([string]$m.RequiredSvn)) { 'n/a' } else { [string]$m.RequiredSvn }
                    $f = if ([string]::IsNullOrWhiteSpace([string]$m.FirmwareSvn)) { 'absent' } else { [string]$m.FirmwareSvn }
                    "$($m.Component)(staged=$r, raw firmware=$f)"
                }
                $firmwareHasAnySvn       = (@($mc | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.FirmwareSvn) }).Count -gt 0)
                $everyMissingHasPriorSvn = (@($mc | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.FirmwareSvn) }).Count -eq 0)
                $svnStuckAfterBoot       = ($null -ne $svnStatus -and $null -ne $svnStatus.SvnNotApplied -and $svnStatus.SvnNotApplied)
                if ($mc.Count -lt 3 -and $svnStuckAfterBoot) {
                    $severity  = 'WARNING'
                    $qualifier = 'SVN update not applied after reboot - firmware refused to absorb, reboot will not resolve'
                }
                elseif ($mc.Count -lt 3 -and $everyMissingHasPriorSvn) {
                    $severity  = 'INFO'
                    $qualifier = 'pending SVN update - firmware at prior SVN for missing component(s), reboot will apply'
                }
                elseif ($mc.Count -lt 3) {
                    $severity  = 'WARNING'
                    $qualifier = 'partial firmware commit - component-asymmetric, reboot will not resolve'
                }
                elseif ($firmwareHasAnySvn) {
                    $severity  = 'INFO'
                    $qualifier = 'all three missing, firmware has prior SVN entries - consistent with pre-reboot state'
                }
                else {
                    $severity  = 'INFO'
                    $qualifier = 'all three missing, firmware has no prior SVN entries - pre-rollout state (Stage 1/2, awaiting Microsoft enforcement June 2026 - 2027)'
                }
                Write-Log $severity "SVN components not absorbed by firmware ($qualifier): $($descLines -join ', ')"
            }
        }
        else {
            Write-Log "INFO" "DBX validation skipped: $($dbxValidationResult.Error)"
        }
    }
    if ($null -ne $dbxValidationResult -and $dbxValidationResult.Succeeded) {
        $cardProperties['DBX Validation'] = Build-DbxValidationSection -Format 'Html' -Result $dbxValidationResult
    }
    # Bucket / confidence (from event message metadata)
    if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus -and $null -ne $certStatus.Confidence) {
        $cardProperties['Rollout Tier'] = Build-RolloutTierSection -Format 'Html'
    }
    # Scheduled task status (only when Secure Boot is Enabled)
    if ($secureBoot -eq 'Enabled') {
        $cardProperties['Update Task'] = Build-UpdateTaskSection -Format 'Html'
    }
    # Opt-in status (only when Secure Boot is Enabled and check ran)
    if ($secureBoot -eq 'Enabled' -and $null -ne $optInStatus) {
        $cardProperties['Opt-In Status'] = Build-OptInSection -Format 'Html'
    }
    
    $cardInfo = [PSCustomObject]$cardProperties
    
    $cardHtml = Get-NinjaOneInfoCard `
        -Title $CardTitle `
        -Data $cardInfo `
        -Icon $CardIcon `
        -BackgroundGradient $CardBackgroundGradient `
        -BorderRadius $CardBorderRadius `
        -IconColor $cardIconColor
    
    # -----------------------------------------------
    # Step 5: Write fields to NinjaRMM
    # -----------------------------------------------
    if ($SaveStatusLocal) {
        # Local HTML card: reuse the exact same Html-format output as Ninja (1:1 parity),
        # then swap FontAwesome <i> icons → emoji via Convert-FaIconsToEmoji.
        $localCardProperties = [ordered]@{
            'Secure Boot' = Convert-FaIconsToEmoji $statusRowHtml
            'Detail'      = Convert-FaIconsToEmoji $detailRowHtml
        }
        if ($null -ne $eventRowHtml) {
            $localCardProperties['Last Event'] = Convert-FaIconsToEmoji $eventRowHtml
        }
        # Build-* functions called with 'Html' format (same as Ninja card) for guaranteed parity
        if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus -and $certStatus.EventSummary.Count -gt 0) {
            $localCardProperties['Event Log'] = Convert-FaIconsToEmoji (Build-EventLogSection -Format 'Html')
        }
        if ($secureBoot -eq 'Enabled') {
            $localCardProperties['Certificates'] = Convert-FaIconsToEmoji (Build-CertInventorySection -Format 'Html')
        }
        # PK Security Alert - parity with Ninja card. Built with 'Local' Format so the header icon renders
        # as an emoji (Format-CardIcon -> '[Times]') instead of FontAwesome. Rest of the body is format-agnostic
        # HTML (details/links/code) that renders identically in both targets.
        if ($statusKey -eq 'PKUntrusted') {
            $localCardProperties['PK Security Alert'] = Build-PkSecurityAlertSection -Format 'Local'
        }
        # Factory defaults - parity with Ninja card. Only surfaced when something is missing.
        if ($secureBoot -eq 'Enabled' -and ($defaultsAllMissing -or $defaultsSomeMissing)) {
            $localCardProperties['Factory Defaults'] = Convert-FaIconsToEmoji (Build-FactoryDefaultsSection -Format 'Html')
        }
        # HP BIOS CA 2023 interface - parity with Ninja card.
        if ($isHpManufacturer -and $null -ne $hpBios -and $hpBios.Available) {
            $hpContent = Build-HpBiosSection -Format 'Html' -HpBios $hpBios -StuckPattern $hpStuckPattern -Remediation $hpRemediation
            if ($null -ne $hpContent) { $localCardProperties['HP BIOS CA 2023'] = Convert-FaIconsToEmoji $hpContent }
        }
        if ($secureBoot -eq 'Enabled' -and $null -ne $servicingStatus) {
            $servContent = Build-ServicingSection -Format 'Html'
            if ($null -ne $servContent) { $localCardProperties['Servicing'] = Convert-FaIconsToEmoji $servContent }
        }
        if ($secureBoot -eq 'Enabled' -and ($hasRegistryManifest -or $hasEventMitigations)) {
            $localCardProperties['Updates'] = Convert-FaIconsToEmoji (Build-UpdatesSection -Format 'Html')
        }
        elseif ($secureBoot -eq 'Enabled') {
            $chk = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            $localCardProperties['Updates'] = "$chk No Updates Pending <span style='color:#26A644;'>(all applied)</span>"
        }
        if ($secureBoot -eq 'Enabled' -and $null -ne $svnStatus) {
            $localCardProperties[(Convert-FaIconsToEmoji $svnSectionTitle)] = Convert-FaIconsToEmoji (Build-SvnComplianceSection -Format 'Html')
        }
        if ($null -ne $svnBitLockerSafetyResult) {
            $svnBitLockerContent = Build-SvnBitLockerSection -Format 'Html' -Result $svnBitLockerSafetyResult
            if ($null -ne $svnBitLockerContent) {
                $localCardProperties['SVN BitLocker Safety'] = Convert-FaIconsToEmoji $svnBitLockerContent
            }
        }
        # Boot Media - parity with Ninja card. Reuses the cached $bootMediaResult from Step 4.
        if ($null -ne $bootMediaResult -and $bootMediaResult.Outdated.Count -gt 0) {
            $localCardProperties['Boot Media'] = Convert-FaIconsToEmoji (Build-BootMediaSection -Format 'Html' -Result $bootMediaResult)
        }
        # KEK Update Available - parity with Ninja card. Reuses the cached $kekLookupResult from Step 4.
        if ($null -ne $kekLookupResult -and $kekLookupResult.Succeeded -and $kekLookupResult.Available) {
            $localCardProperties['KEK Update Available'] = Convert-FaIconsToEmoji (Build-KekUpdateAvailabilitySection -Format 'Html' -Result $kekLookupResult)
        }
        # DBX Validation - parity with Ninja card. Reuses the cached $dbxValidationResult from Step 4 so the
        # staged-file comparison runs only once per execution. 'Html' Format + Convert-FaIconsToEmoji for
        # consistency with the other Build-* calls in this block.
        if ($null -ne $dbxValidationResult -and $dbxValidationResult.Succeeded) {
            $localCardProperties['DBX Validation'] = Convert-FaIconsToEmoji (Build-DbxValidationSection -Format 'Html' -Result $dbxValidationResult)
        }
        if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus -and $null -ne $certStatus.Confidence) {
            $localCardProperties['Rollout Tier'] = Convert-FaIconsToEmoji (Build-RolloutTierSection -Format 'Html')
        }
        if ($secureBoot -eq 'Enabled') {
            $localCardProperties['Update Task'] = Convert-FaIconsToEmoji (Build-UpdateTaskSection -Format 'Html')
        }
        if ($secureBoot -eq 'Enabled' -and $null -ne $optInStatus) {
            $localCardProperties['Opt-In Status'] = Convert-FaIconsToEmoji (Build-OptInSection -Format 'Html')
        }
        
        $localCardInfo = [PSCustomObject]$localCardProperties
        
        $localCardTitle = "Secure Boot Status"
        
        $localCardHtml = Get-LocalHtmlDocument `
            -Title $localCardTitle `
            -Data $localCardInfo `
            -AccentColor $cardIconColor
        
        # -----------------------------------------------
        # Step 5.5: Save status locally if enabled
        # -----------------------------------------------
        $systemDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive
        $logDir = "$systemDrive\Logs\SecureBoot"
        if (-not (Test-Path $logDir)) {
            try {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            catch {
                Write-Log "ERROR" "Failed to create local log directory: $($_.Exception.Message)"
            }
        }
        $txtFile = Join-Path $logDir "SecureBootStatus.txt"
        $htmlFile = Join-Path $logDir "SecureBootStatusCard.html"
        try {
            $plainText | Out-File -FilePath $txtFile -Encoding utf8 -Force
            $localCardHtml | Out-File -FilePath $htmlFile -Encoding utf8 -Force
            Write-Log "SUCCESS" "Saved status to local files: $txtFile and $htmlFile"
            #Write-Host "`nSaved local status files:`n- Text: $txtFile`n- HTML: $htmlFile"
            #Write-Host "`nLocal Text Status Content:"
            #Get-Content $txtFile | Write-Host
        }
        catch {
            Write-Log "ERROR" "Failed to save local status files: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "`n=== Writing NinjaRMM Custom Fields ==="
        
        Write-Log "INFO" "Writing status card to '$StatusCardFieldName'"
        try {
            Invoke-NinjaPropertySetPiped -FieldName $StatusCardFieldName -Html $cardHtml
            Write-Log "SUCCESS" "Status card written to '$StatusCardFieldName'"
        }
        catch {
            Write-Log "ERROR" "Failed to write status card: $($_.Exception.Message)"
        }
        
        Write-Log "INFO" "Writing plain-text status to '$PlainTextFieldName'"
        try {
            # Ninja text fields have a 200-char limit; truncate only for the Ninja write
            $ninjaPlainText = if ($plainText.Length -gt 200) { $plainText.Substring(0, 197) + '...' } else { $plainText }
            Invoke-NinjaPropertySet -FieldName $PlainTextFieldName -Value $ninjaPlainText
            Write-Log "SUCCESS" "Plain-text status written to '$PlainTextFieldName'"
        }
        catch {
            Write-Log "ERROR" "Failed to write plain-text status: $($_.Exception.Message)"
        }
    }
    
    # -----------------------------------------------
    # Step 6: Console summary
    # -----------------------------------------------
    Write-Host "`n--- SECURE BOOT CERTIFICATE STATUS ---"
    Write-Host "Secure Boot : $secureBoot"
    Write-Host "Final State : $statusKey"
    Write-Host "Plain Text  : $plainText"
    if ($certStatus -and -not $triggeredOsUpdate) {
        Write-Host "Event Detail: $($certStatus.EventMessage)"
    }
    if ($secureBoot -eq 'Enabled') {
        Write-Host "KEK 2023    : $(if ($has2023InKek) { 'Present' } else { 'Missing' })"
        Write-Host "DB 2023     : $(if ($has2023InDb) { $dbCertsFound -join ', ' } else { 'None found' })"
        Write-Host "Update Task : $(if ($scheduledTaskPresent) { 'Present' } else { 'Missing' })"
        Write-Host "OS Writable : $dbIsOsWritable"
        Write-Host "Opt-In      : $(if ($null -ne $optInStatus) { $optInStatus.Summary } else { 'N/A' })"
        if ($null -ne $servicingStatus -and $null -ne $servicingStatus.UEFICA2023Status) {
            Write-Host "Servicing   : $($servicingStatus.UEFICA2023Status)"
            if ($null -ne $servicingStatus.WindowsUEFICA2023Capable) {
                $capDesc = switch ($servicingStatus.WindowsUEFICA2023Capable) { 1 { 'Cert in DB' }; 2 { 'Cert in DB + 2023 boot mgr' }; default { 'Not in DB' } }
                Write-Host "Boot Mgr    : $capDesc (Capable=$($servicingStatus.WindowsUEFICA2023Capable))"
            }
            if ($null -ne $servicingStatus.UEFICA2023Error -and $servicingStatus.UEFICA2023Error -ne 0) {
                Write-Host "Serv Error  : $($servicingStatus.UEFICA2023ErrorHex) - $($servicingStatus.UEFICA2023ErrorMessage)"
            }
            if ($null -ne $servicingStatus.CanAttemptUpdateAfter -and $servicingStatus.CanAttemptUpdateAfter -gt (Get-Date)) {
                Write-Host "Next Attempt: $($servicingStatus.CanAttemptUpdateAfter.ToString('yyyy-MM-dd HH:mm'))"
            }
        }
        if ($null -ne $certStatus -and $null -ne $certStatus.Confidence) {
            Write-Host "Confidence  : $($certStatus.Confidence)"
        }
        if ($null -ne $certStatus -and $null -ne $certStatus.SkipReason) {
            Write-Host "Skip Reason : $($certStatus.SkipReason)"
        }
        if ($null -ne $certStatus -and $null -ne $certStatus.RebootCorrelation) {
            $rc = $certStatus.RebootCorrelation
            if ($rc.Confirmed) {
                Write-Host "Reboot Link : 1800 -> reboot ($($rc.BootTimes[-1].ToString('yyyy-MM-dd HH:mm'))) -> 1799 (confirmed)"
            }
            else {
                Write-Host "Reboot Link : 1800 -> 1799 (no reboot found between them)"
            }
        }
        if ($pending1808Note) {
            Write-Host "1808 Status : Expected on next scheduled task cycle (servicing confirms Updated)"
        }
        if ($null -ne $optInStatus -and $optInStatus.EffectiveAvailable -ne 0) {
            $manifestLabel = if ($allApplied) { 'Manifest    :' } else { 'Pending     :' }
            Write-Host "$manifestLabel $($optInStatus.AvailableUpdatesMeaning -join '; ')"
            if ($manifestPending.Count -gt 0) {
                Write-Host "Still Needed: $($manifestPending -join ', ')$(if ($pendingReboot) { ' (reboot pending)' })"
            }
        }
        if ($null -ne $svnStatus) {
            # Mirror Build-SvnComplianceSection's partial-commit detection so console output
            # doesn't diverge from the card label for operators reading both.
            $consolePartialCommit = $false
            $consolePartialNames  = @()
            if ($null -ne $dbxValidationResult -and $dbxValidationResult.Succeeded) {
                $cm = @($dbxValidationResult.MissingComponents)
                if ($cm.Count -gt 0 -and $cm.Count -lt 3) {
                    $consolePartialCommit = $true
                    $consolePartialNames  = @($cm | ForEach-Object { $_.Component })
                }
            }
            if ($svnStatus.IsCompliant) {
                Write-Host "SVN Status  : Compliant"
            }
            elseif ($consolePartialCommit) {
                Write-Host "SVN Status  : Firmware partial-commit: $($consolePartialNames -join ', ') SVN rejected (reboot will not resolve)"
            }
            elseif ($svnStatus.RebootPending) {
                Write-Host "SVN Status  : Pending SVN reboot - firmware SVN update not yet applied"
            }
            elseif ($svnStatus.RevocationAppliedPendingReboot) {
                Write-Host "SVN Status  : 2011 CA revocation pending reboot"
            }
            elseif ($svnStatus.RevocationPending) {
                Write-Host "SVN Status  : Pending - 2011 CA not yet revoked"
            }
            else {
                Write-Host "SVN Status  : $($svnStatus.ComplianceStatus)"
            }
            # Identical SVN console shape across every stage. Firmware/Staged are raw-DBX
            # canonical values; BootMgr comes from the cmdlet when present, 'N/A' otherwise.
            # CdBoot/WdsMgr are always raw-DBX (cmdlet doesn't expose them).
            Write-Host "Firmware SVN: $($svnStatus.FirmwareSVN)"
            Write-Host "BootMgr SVN : $($svnStatus.BootManagerSVN)"
            Write-Host "Staged SVN  : $($svnStatus.StagedSVN)"
            Write-Host "CdBoot SVN  : $($svnStatus.CdBootSVN)"
            Write-Host "WdsMgr SVN  : $($svnStatus.WdsMgrSVN)"
            if ($svnStatus.SvnUpdatePending) {
                Write-Host "SVN Pending : DBXUpdateSVN.bin $($svnStatus.WindowsUpdateSVN) not yet in DBX"
            }
            if ($null -ne $svnStatus.Stage) {
                Write-Host "SVN Stage   : $($svnStatus.Stage) - $($svnStatus.StageDetail)"
            }
        }
        if ($null -ne $svnEnforcementResult) {
            $svnRebootMessage = if ($svnEnforcementResult.RebootRequired -and
                                    $null -ne $svnBitLockerSafetyResult -and
                                    $svnBitLockerSafetyResult.UnsafePendingManifest) {
                ' (DO NOT REBOOT - unsafe Stage 3/4 manifest)'
            }
            elseif ($svnEnforcementResult.RebootRequired -and
                                    $null -ne $svnBitLockerSafetyResult -and
                                    $svnBitLockerSafetyResult.Status -eq 'Failed' -and
                                    $svnBitLockerSafetyResult.PendingManifest) {
                ' (DO NOT REBOOT - BitLocker suspension failed)'
            }
            elseif ($svnEnforcementResult.RebootRequired) {
                ' (reboot required)'
            }
            else {
                ''
            }
            Write-Host "SVN Enforce : $($svnEnforcementResult.ActionsApplied.Count) applied, $($svnEnforcementResult.ActionsSkipped.Count) skipped$svnRebootMessage"
        }
        elseif ($EnforceSvnCompliance -eq 'Passive') {
            Write-Host "SVN Enforce : Passive (MS enforcement: June 2026 - 2027)"
        }
        if ($null -ne $svnBitLockerSafetyResult) {
            $svnBitLockerConsoleStatus = if ($svnBitLockerSafetyResult.Status -eq 'NotRequired' -and -not $svnBitLockerSafetyResult.Enabled) {
                'Disabled (no Stage 3/4 bits pending)'
            }
            else {
                $svnBitLockerSafetyResult.Status
            }
            Write-Host "SVN BitLocker: $svnBitLockerConsoleStatus"
            if (@($svnBitLockerSafetyResult.SuspendedVolumes).Count -gt 0) {
                Write-Host "  Suspended : $($svnBitLockerSafetyResult.SuspendedVolumes -join ', ') ($($svnBitLockerSafetyResult.RebootCount) reboots)"
            }
            if (@($svnBitLockerSafetyResult.AlreadySuspendedVolumes).Count -gt 0) {
                Write-Host "  Existing  : $($svnBitLockerSafetyResult.AlreadySuspendedVolumes -join ', ') (already suspended; left unchanged)"
            }
            if (@($svnBitLockerSafetyResult.FailedVolumes).Count -gt 0) {
                Write-Host "  Failed    : $($svnBitLockerSafetyResult.FailedVolumes -join ', ')"
            }
            if ($svnBitLockerSafetyResult.UnsafePendingManifest) {
                Write-Host "  WARNING   : Unsafe Stage 3/4 bits could not be cleared - DO NOT REBOOT"
            }
            elseif ($svnBitLockerSafetyResult.Status -eq 'Failed' -and $svnBitLockerSafetyResult.PendingManifest) {
                Write-Host "  WARNING   : Stage 3/4 bits are already pending - DO NOT REBOOT until resolved"
            }
        }
        if ($null -ne $optInStatus -and $null -ne $optInStatus.HighConfidenceOptOut -and $optInStatus.HighConfidenceOptOut -ne 0) {
            Write-Host "HC Opt-Out  : Yes"
        }
        if ($null -ne $optInStatus -and $optInStatus.AvailableUpdatesPolicySet) {
            Write-Host "Policy      : 0x$($optInStatus.AvailableUpdatesPolicy.ToString('X')) (GPO/MDM)"
        }
    }
    Write-Host "--------------------------------------`n"
    
    Write-Host "=== Complete ==="
    Write-Log "SUCCESS" "Secure Boot certificate status check completed"
}
