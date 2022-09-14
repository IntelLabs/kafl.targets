[Defines]
  !include OvmfPkg/OvmfPkgIa32.dsc

[Defines]
  PLATFORM_NAME                  = kAFLDxe
  PLATFORM_GUID                  = DFA5E931-0F48-404F-9AE9-35B80EA9FE56
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/kAFLNull
  SUPPORTED_ARCHITECTURES        = IA32
  BUILD_TARGETS                  = NOOPT|DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT
  FLASH_DEFINITION               = kAFLDxePlatformNullPkg/kAFLDxePlatformIa32.fdf

  # Declared here but defined using build -D OPTION !
  DEFINE SMM_REQUIRE = FALSE
  DEFINE SECURE_BOOT_ENABLE = FALSE
  DEFINE HTTP_BOOT_ENABLE = FALSE
  DEFINE TLS_ENABLE = FALSE

[LibraryClasses]
  kAFLAgentLib|kAFLAgentPkg/Library/kAFLAgentLib/kAFLAgentLib.inf
  kAFLDxeTargetLib|kAFLDxeTargetNullPkg/Library/kAFLDxeTargetLib/kAFLDxeTargetLib.inf

[Components.IA32]
  kAFLDxeHarnessPkg/Dxe/kAFLDxe.inf
  kAFLDxeHarnessPkg/App/kAFLApp.inf

[BuildOptions]

*_*_*_CC_FLAGS             = -DKAFL_HARNESS_EXTERNAL_AGENT_INIT
*_*_*_CC_FLAGS             = $(*_*_*_CC_FLAGS) -DKAFL_HARNESS_EXTERNAL_AGENT_RUN
*_*_*_CC_FLAGS             = $(*_*_*_CC_FLAGS) -DKAFL_HARNESS_EXTERNAL_UEFI_MAIN
