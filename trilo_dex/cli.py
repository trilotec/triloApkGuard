"""CLI entry point for TriloApkGuard."""

import os
import sys

import click

from . import __version__
from .protector import protect_apk, TriloDexError
from .tools import check_tools, ToolNotFoundError


@click.command()
@click.argument("input_apk", type=click.Path(exists=True))
@click.option(
    "-o", "--output", "output_apk",
    type=click.Path(),
    default=None,
    help="Output APK path (default: <input>_protected.apk)",
)
@click.option(
    "--sdk-dir", "sdk_dir",
    type=click.Path(exists=True),
    default=None,
    help="Android SDK root directory (for aapt2/zipalign/apksigner)",
)
@click.option(
    "--skip-sign",
    is_flag=True,
    help="Skip APK signing",
)
@click.option(
    "--skip-verify",
    is_flag=True,
    help="Skip pre-flight tool verification",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
def main(input_apk, output_apk, sdk_dir, skip_sign, skip_verify, verbose):
    """TriloApkGuard - Android APK protection core.

    Encrypts DEX files and injects a stub loader that restores
    protected code at runtime.
    """
    # Default output path
    if output_apk is None:
        base, ext = os.path.splitext(input_apk)
        output_apk = f"{base}_protected{ext}"

    click.echo(f"[*] TriloApkGuard v{__version__}")
    click.echo(f"[*] Input:  {input_apk}")
    click.echo(f"[*] Output: {output_apk}")

    # Pre-flight checks
    if not skip_verify:
        try:
            _check_tools(sdk_dir, skip_sign, verbose)
        except ToolNotFoundError as e:
            click.echo(f"[!] {e}", err=True)
            sys.exit(1)

    # Run protection
    try:
        result = protect_apk(
            input_apk=input_apk,
            output_apk=output_apk,
            sdk_dir=sdk_dir,
            skip_sign=skip_sign,
            verbose=verbose,
            progress_callback=_progress,
        )

        click.echo(f"[+] Protected APK: {result['output']}")
        click.echo(f"[+] DEX files encrypted: {result['dex_count']}")
        click.echo(f"[+] Key scheme: {result['key_scheme']}")
        click.echo(f"[+] Seed: {result['seed_hex']}")
        click.echo(f"[!] Store the seed securely - it is required for debugging!")

    except TriloDexError as e:
        click.echo(f"[!] Error: {e}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\n[!] Interrupted", err=True)
        sys.exit(130)


def _check_tools(sdk_dir: str | None, skip_sign: bool, verbose: bool):
    """Check required external tools."""
    required = ["java", "smali_jar"]
    if not skip_sign and sdk_dir:
        required.extend(["aapt2", "zipalign", "apksigner"])

    status = check_tools(sdk_dir, required=required)

    if verbose:
        click.echo("[*] Tool status:")
        for name in ("java", "smali_jar", "aapt2", "zipalign", "apksigner", "ndk_clang"):
            val = getattr(status, name)
            click.echo(f"    {name}: {val or 'not found'}")


def _progress(step: str, pct: int):
    """Progress callback."""
    click.echo(f"[*] {step}... {pct}%")


if __name__ == "__main__":
    main()
