# RenReader runtime notices

RenReader embeds modified Ren'Py runtimes and their dependencies. Ren'Py is by
Tom Rothamel and its contributors. The complete upstream license and copyright
notices shipped with each exact official SDK are in that runtime resource
bundle's `LICENSE.txt`. `SharedPlatform-LICENSE.txt` is the official Ren'Py 8.5.3
notice covering the shared SDL/UIKit/MetalANGLE platform layer. These files must
remain available in binary distributions.

The official SDK and Renios archives are fetched from
<https://www.renpy.org/dl/> and verified against the official SHA-256 checksums.
Each bundle's `provenance.json` records the exact archive URLs and checksums,
Python ABI, and hashes of the RenReader adapter sources used to prepare it.
The tracked `RuntimeKit/Notices` directory keeps a copy of each built profile's
upstream license and provenance without including the large SDK caches.

Upstream source and dependency build recipes:

- <https://github.com/renpy/renpy>
- <https://github.com/renpy/renpy-build>
- <https://github.com/renpy/pygame_sdl2> (older Ren'Py releases)
- <https://github.com/kivy/pyobjus>
- <https://github.com/kakashidinho/metalangle>

RenReader modifications are distributed in `RuntimeKit/Native`,
`RuntimeKit/Python`, and `Scripts/runtime`. They add one private Mach-O entry
point per exact runtime, keep its CPython interpreter alive without finalizing
it, return each title session to the native host, share one SDL/UIKit platform
image, route managed save/log/token directories, and add bounded host command
and event queues. The build script applies explicit patches to the bundled
upstream bootstrap: import the engine once per interpreter, return on host
stop/title quit, and skip process-exit callbacks after a completed session reset.

Several dependencies are under the GNU LGPL. A production distribution must
provide the corresponding dependency sources and build/relink materials required
by those licenses, including the exact modifications. The source URLs and these
notices are provenance records; they do not replace that distribution obligation.
See the app's Open Source and Third-Party Licenses page for the materials
supplied with the installed build. The source package inventory and build
instructions describe its exact delivery scope and relinking procedure.

## Edition without the Live2D SDK

This edition does not ship Live2D Cubism Core or Cubism Native Framework.
Ren'Py's open-source compatibility APIs remain; creating a Live2D model
returns an unsupported-feature error. No Live2D models are bundled.

The exact 7.4.11, 7.5.3 and 8.0.3 Mesh extensions gain the later official public
setters without changing their `.pxd` layouts. 7.4.11 additionally exposes a
scoped texture-extent property based on the later official correction; ordinary
and legacy renderer paths retain their previous behavior. Each modified framework
contains its patch, exact input/source/header/object hashes and upstream notice.

## Post-assembly host adapter update

After the recorded resource assembly, RenReader updated its host adapter to
select resume checkpoints using the active Ren'Py save location and to
validate explicitly requested save slot names. The original provenance.json
continues to describe the resource-assembly source state and is not a hash
of later host-adapter revisions.

The prior base/rr_host.py SHA-256 was
`0a7a271d1a9016deab9edeaccab9df66ab7817282c727dca3e1d3aa18ab21a73`;
the subsequent resume revision of base/rr_host.py was
`e9d488f7dfafa7d099f99ebf3cf6024b0b7480c8cec8095e9d68cd1331306562`.
The corresponding host bridge source is retained in RuntimeKit/Bridge.

A later host-only revision provides a fallback confirmation for untrusted
saves when the game has no confirmation handler. It retains existing game
prompts and verifies candidate signing keys before offering trust. Fallback
risk text and controls are in English; game-supplied text depends on the
game's fonts. That revision's base/rr_host.py SHA-256 was
`b06203e5b12e383f0da8bcb982646fb22b0f1af8671342cbbf51428db2817228`.

A subsequent host-only revision supplies fixed Chinese trust warnings and
controls using a subset of Noto Sans SC under the SIL Open Font License 1.1;
the license is included at LegalResources/renreader-trust-NotoSansSC-OFL.txt. The subset
`renreader-trust-7e42.ttf` has SHA-256
`fefb02aee876d50f36fd84fc0e3780e6f7441a9ca26a0c913fd63a278d61da78`.
It is used only for host-provided text. If the matching font cannot be loaded,
the host warning and controls fall back to English; game-supplied messages
continue to use the game's font. The updated base/rr_host.py SHA-256 is
`98d16fcef2e9652980e1665628988ad6e40360da7a8881a5b58181c9abd8ccc3`.
