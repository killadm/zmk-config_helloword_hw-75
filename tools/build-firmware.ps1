param(
  [string[]] $Target,
  [switch] $KeyboardOnly,
  [switch] $SkipImageBuild,
  [switch] $NoPristine,
  [switch] $UpdateModules,
  [switch] $RefreshPythonDeps,
  [string] $Image = "hw75-zmk-build:local"
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DockerfileDir = Join-Path $RepoRoot "tools/docker/firmware"

function Invoke-Native {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Command,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Arguments
  )

  & $Command @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$Command failed with exit code $LASTEXITCODE"
  }
}

$DefaultTargets = @(
  "hw75_keyboard@1.1:hw75_keyboard.keymap",
  "hw75_keyboard@1.2:hw75_keyboard.keymap",
  "hw75_dynamic@A:hw75_dynamic.keymap",
  "hw75_dynamic@B:hw75_dynamic.keymap"
)

if ($KeyboardOnly -and -not $Target) {
  $Target = @(
    "hw75_keyboard@1.1:hw75_keyboard.keymap",
    "hw75_keyboard@1.2:hw75_keyboard.keymap"
  )
}

if (-not $Target) {
  $Target = $DefaultTargets
}
else {
  $Target = $Target | ForEach-Object { $_ -split "," } | Where-Object { $_.Trim() }
}

function Convert-TargetSpec {
  param([string] $Spec)

  $parts = $Spec.Split(":", 2)
  $board = $parts[0].Trim()
  if (-not $board) {
    throw "Invalid target: $Spec"
  }

  $keymap = if ($parts.Count -gt 1 -and $parts[1].Trim()) { $parts[1].Trim() } else { $null }
  if (-not $keymap) {
    if ($board.StartsWith("hw75_dynamic")) {
      $keymap = "hw75_dynamic.keymap"
    } else {
      $keymap = "hw75_keyboard.keymap"
    }
  }

  [pscustomobject]@{
    Board = $board
    Keymap = $keymap
    BuildDir = "build/$($board -replace '[^A-Za-z0-9_.-]', '_')"
  }
}

$Targets = $Target | ForEach-Object { Convert-TargetSpec $_ }

if (-not $SkipImageBuild) {
  Invoke-Native docker build -t $Image $DockerfileDir
}

$targetLines = ($Targets | ForEach-Object {
  "build_one '$($_.Board)' '$($_.Keymap)' '$($_.BuildDir)'"
}) -join "`n"

$pristineFlag = if ($NoPristine) { "" } else { "-p always" }

$script = @"
set -euo pipefail
cd /work

if [ ! -d .west ]; then
  west init -l config
  need_west_update=1
else
  need_west_update=0
fi

if [ ! -d zephyr ] || [ ! -d zmk/app ]; then
  need_west_update=1
fi

if [ "$need_west_update" = "1" ] || [ "${UPDATE_MODULES:-0}" = "1" ]; then
  west update
else
  echo "==> Skipping west update; pass -UpdateModules to refresh modules"
fi

west zephyr-export

if [ -f zephyr/scripts/requirements-extras.txt ]; then
  sed -i 's/clang-format>=1.13x/clang-format>=1.13/g' zephyr/scripts/requirements-extras.txt
fi

if [ "${REFRESH_PYTHON_DEPS:-0}" = "1" ]; then
  pip install --upgrade pip packaging setuptools wheel
  pip install -r zephyr/scripts/requirements.txt
  pip install 'protobuf<4.0.0'
else
  echo "==> Skipping Python dependency refresh; pass -RefreshPythonDeps to reinstall"
fi

git config --global --add safe.directory /work || true

find . -name 'usb_comm.pb.c' -delete
find . -name 'usb_comm.pb.h' -delete

build_one() {
  board="`$1"
  keymap="`$2"
  build_dir="`$3"

  echo "==> Building `${board} with `${keymap}"
  west build $pristineFlag -d "`${build_dir}" -s zmk/app -b "`${board}" -- \
    -DZMK_CONFIG=/work/config \
    -DKEYMAP_FILE=/work/config/"`${keymap}"

  bin="`${build_dir}/zephyr/zmk.bin"
  map="`${build_dir}/zephyr/zephyr.map"
  if [ -f "`${bin}" ]; then
    size=`$(stat -c %s "`${bin}")
    printf 'SIZE %s %s bytes\n' "`${board}" "`${size}"
    if echo "`${board}" | grep -q '^hw75_keyboard@' && [ "`${size}" -gt 106496 ]; then
      echo "ERROR: `${board} zmk.bin exceeds 104KB code partition (`${size} bytes)" >&2
      exit 2
    fi
  fi
  if [ -f "`${map}" ]; then
    cp "`${map}" "`${build_dir}/zephyr/`${board//[^A-Za-z0-9_.-]/_}.map"
  fi
}

$targetLines
"@

$encodedScript = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script))
$repoForDocker = $RepoRoot -replace "\\", "/"

$dockerArgs = @(
  "run",
  "--rm",
  "-e", "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python",
  "-e", "UPDATE_MODULES=$([int]$UpdateModules.IsPresent)",
  "-e", "REFRESH_PYTHON_DEPS=$([int]$RefreshPythonDeps.IsPresent)",
  "-v", "${repoForDocker}:/work",
  "-w", "/work",
  $Image,
  "bash",
  "-lc",
  "echo $encodedScript | base64 -d | bash"
)

Invoke-Native docker @dockerArgs
