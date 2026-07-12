#!/usr/bin/env python3
"""构建风险报告 - 按 Electron/CEF exploit 性重新评估"""

import json
from datetime import datetime
from pathlib import Path


# 组件分类：是否影响 Electron/CEF
SHARED_COMPONENTS = {
    'v8': 'V8',
    'turboshaft': 'TurboShaft',
    'turbofan': 'TurboFan',
    'maglev': 'MagLev',
    'sparkplug': 'Sparkplug',
    'liftoff': 'Liftoff',
    'skia': 'Skia',
    'blink': 'Blink',
    'webrtc': 'WebRTC',
    'angle': 'ANGLE',
    'dawn': 'Dawn',
    'pdfium': 'PDFium',
    'freetype': 'FreeType',
    'harfbuzz': 'HarfBuzz',
    'ffmpeg': 'FFmpeg',
    'libvpx': 'libvpx',
    'libwebp': 'libwebp',
    'libpng': 'libpng',
    'libjpeg': 'libjpeg',
    'sqlite': 'SQLite',
    'boringssl': 'BoringSSL',
    'zlib': 'zlib',
    'icu': 'ICU',
    'mojo': 'Mojo',
    'ipc': 'IPC',
    'sandbox': 'Sandbox',
    'gpu': 'GPU',
    'css': 'CSS',
    'dom': 'DOM',
    'html': 'HTML',
    'webgpu': 'WebGPU',
    'webgl': 'WebGL',
    'webassembly': 'WebAssembly',
    'wasm': 'WebAssembly',
    'canvas': 'Canvas',
    'web audio': 'WebAudio',
    'web codecs': 'WebCodecs',
    'web transports': 'WebTransport',
    'websocket': 'WebSocket',
    'webusb': 'WebUSB',
    'webnfc': 'WebNFC',
    'webbluetooth': 'WebBluetooth',
    'indexeddb': 'IndexedDB',
    'service worker': 'ServiceWorker',
    'web share': 'WebShare',
    'screen capture': 'ScreenCapture',
    'web xr': 'WebXR',
    'picture in picture': 'PictureInPicture',
    'fullscreen': 'Fullscreen',
    'pointer lock': 'PointerLock',
    'notifications': 'Notifications',
    'permissions': 'Permissions',
    'site isolation': 'SiteIsolation',
    'navigation': 'Navigation',
    'loader': 'Loader',
    'network': 'Network',
    'url': 'URL',
    'intents': 'Intents',
    'fenced frame': 'FencedFrame',
    'portals': 'Portals',
    'prerender': 'Prerender',
    'media': 'Media',
    'video': 'Video',
    'audio': 'Audio',
    'speech': 'Speech',
    'camera': 'Camera',
    'microphone': 'Microphone',
    'clipboard': 'Clipboard',
    'file system': 'FileSystem',
    'storage': 'Storage',
    'cache': 'Cache',
    'cookie': 'Cookie',
    'devtools': 'DevTools',
    'inspector': 'Inspector',
    'tracing': 'Tracing',
    'metrics': 'Metrics',
    'vulkan': 'Vulkan',
    'opengl': 'OpenGL',
    'directx': 'DirectX',
    'metal': 'Metal',
    'heap': 'Heap',
    'garbage collection': 'GC',
    'jit': 'JIT',
    'regexp': 'RegExp',
    'intl': 'Intl',
    'wasm gc': 'WasmGC',
}

# 组件版本粒度：标记哪些组件独立于 Chromium release 开发，
# 需要比 Chromium 版本更细的跟踪粒度
COMPONENT_GRANULARITY = {
    # V8 及其子编译器 — 独立仓库，tip-of-tree 开发，cherry-pick 进 Chromium
    'V8':           {'granularity': 'v8',       'note': 'V8 independently developed; same Chromium version may have different V8 snapshots across Chrome/Electron/self-built'},
    'TurboShaft':   {'granularity': 'v8',       'note': 'V8 sub-compiler'},
    'TurboFan':     {'granularity': 'v8',       'note': 'V8 sub-compiler'},
    'MagLev':       {'granularity': 'v8',       'note': 'V8 sub-compiler'},
    'Sparkplug':    {'granularity': 'v8',       'note': 'V8 sub-compiler'},
    'Liftoff':      {'granularity': 'v8',       'note': 'V8 sub-compiler'},
    'RegExp':       {'granularity': 'v8',       'note': 'V8 sub-component'},
    'Intl':         {'granularity': 'v8',       'note': 'V8 sub-component'},
    'JIT':          {'granularity': 'v8',       'note': 'V8 JIT infrastructure'},
    'GC':           {'granularity': 'v8',       'note': 'V8 garbage collector'},
    'Heap':         {'granularity': 'v8',       'note': 'V8 heap management'},
    'WasmGC':       {'granularity': 'v8',       'note': 'V8 Wasm GC'},

    # 可能有独立发布节奏的组件
    'ANGLE':        {'granularity': 'angle',    'note': 'ANGLE has own repo but typically syncs with Chromium milestones'},
    'Dawn':         {'granularity': 'dawn',     'note': 'Dawn/WebGPU has independent development pace'},
    'WebRTC':       {'granularity': 'webrtc',   'note': 'WebRTC has separate release branches'},
    'PDFium':       {'granularity': 'pdfium',   'note': 'PDFium has own repo, may lag Chromium releases'},
    'FFmpeg':       {'granularity': 'ffmpeg',   'note': 'FFmpeg versioned independently'},
    'FreeType':     {'granularity': 'freetype', 'note': 'FreeType versioned independently'},
    'HarfBuzz':     {'granularity': 'harfbuzz', 'note': 'HarfBuzz versioned independently'},

    # 默认：与 Chromium release 同步的组件
    # Blink, Skia, Mojo, IPC, Network, GPU, CSS, DOM, HTML, 
    # WebGPU, WebGL, WebAssembly, Canvas, WebAudio, IndexedDB,
    # ServiceWorker, ScreenCapture, WebXR, PictureInPicture,
    # Fullscreen, Notifications, Permissions, Navigation, Loader,
    # Media, Video, Audio, Speech, Camera, Clipboard, FileSystem,
    # Storage, Cache, Cookie, DevTools, Vulkan, OpenGL, Metal 等
    # → 所有未显式列出的组件使用默认 granularity='chromium'
}

# 默认 granularity
DEFAULT_GRANULARITY = 'chromium'

CHROME_ONLY = {
    'extensions': 'Extensions',
    'autofill': 'Autofill',
    'payments': 'Payments',
    'password manager': 'PasswordManager',
    'sync': 'Sync',
    'omnibox': 'Omnibox',
    'toolbar': 'Toolbar',
    'bookmarks': 'Bookmarks',
    'history': 'History',
    'downloads': 'Downloads',
    'safe browsing': 'SafeBrowsing',
    'cast': 'Cast',
    'media router': 'MediaRouter',
    'chrome apps': 'ChromeApps',
    'guest': 'Guest',
    'profile': 'Profile',
    'enterprise': 'Enterprise',
    'policy': 'Policy',
    'managed': 'Managed',
    'signin': 'SignIn',
    'identity': 'Identity',
    'gaia': 'Gaia',
    'lens': 'Lens',
    'side panel': 'SidePanel',
    'tab search': 'TabSearch',
    'tab groups': 'TabGroups',
    'reading mode': 'ReadingMode',
    'screenshots': 'Screenshots',
    'page info': 'PageInfo',
    'settings': 'Settings',
    'prefs': 'Prefs',
    'custom tabs': 'CustomTabs',
    'webapk': 'WebAPK',
    'digital goods': 'DigitalGoods',
}


def load_json(filepath):
    path = Path(filepath)
    if not path.exists():
        print(f"Warning: {filepath} not found")
        return {}
    return json.loads(path.read_text())


def extract_component(description):
    """从 CVE 描述中提取受影响的 Chromium 组件"""
    desc = (description or '').lower()
    
    # 检查共享组件
    for kw, comp in SHARED_COMPONENTS.items():
        if kw in desc:
            return comp, 'shared'
    
    # 检查浏览器专属
    for kw, comp in CHROME_ONLY.items():
        if kw in desc:
            return comp, 'chrome'
    
    # 从描述中尝试匹配通用模式
    if ' in ' in desc:
        parts = desc.split(' in ')
        if len(parts) >= 2:
            context = parts[-2] if len(parts) > 2 else parts[0]
            context = context.split('prior')[0].strip()
            if len(context) < 40:
                return context, 'shared'
    
    return 'Unknown', 'unknown'


def assess_exploitability(cve):
    """评估在 Electron/CEF 中的 exploit 性"""
    
    is_kev = cve.get('in_kev', False)
    is_wild = cve.get('in_the_wild', False)
    has_poc = cve.get('has_public_exploit', False)
    component_type = cve.get('component_type', 'unknown')
    has_gerrit = bool(cve.get('gerrit_url'))
    has_bug = bool(cve.get('bug_url'))
    
    evidence = []
    
    # Chrome 专属组件 → 不适用
    if component_type == 'chrome':
        return {
            'level': 'Not Applicable',
            'label': 'N/A',
            'order': 0,
            'reason': ' | '.join(evidence) if evidence else 'Chrome-specific component, not in Electron/CEF',
            'has_poc': has_poc
        }
    
    # KEV + 共享组件 → 已确认可 exploit
    if is_kev and component_type == 'shared':
        evidence.append('CISA KEV confirmed exploitation')
        if is_wild: evidence.append('Google confirmed in-the-wild')
        if has_poc: evidence.append('Public exploit/PoC available')
        if has_gerrit: evidence.append('Public patch available')
        if has_bug: evidence.append('Bug tracker details public')
        return {
            'level': 'Confirmed',
            'label': 'CONFIRMED',
            'order': 5,
            'reason': ' | '.join(evidence),
            'has_poc': has_poc
        }
    
    # 在野 + 共享组件 → 高可能性
    if is_wild and component_type == 'shared':
        evidence.append('Google confirmed in-the-wild')
        if has_poc: evidence.append('Public exploit/PoC available')
        if has_gerrit: evidence.append('Public patch available')
        return {
            'level': 'High',
            'label': 'HIGH',
            'order': 4,
            'reason': ' | '.join(evidence) if evidence else 'Exploited in Chrome, shared component in Electron/CEF',
            'has_poc': has_poc
        }
    
    # 共享组件 + 有公开 PoC → 已有 PoC 参考（比仅有 patch 更高）
    if component_type == 'shared' and has_poc:
        evidence.append('Public exploit/PoC available')
        if has_gerrit: evidence.append('Public patch available')
        return {
            'level': 'Likely',
            'label': 'LIKELY',
            'order': 3,
            'reason': ' | '.join(evidence),
            'has_poc': has_poc
        }
    
    # 共享组件 + 有补丁 → 已有公开 PoC 参考
    if component_type == 'shared' and has_gerrit:
        return {
            'level': 'Likely',
            'label': 'LIKELY',
            'order': 3,
            'reason': 'Shared component, public patch provides PoC reference',
            'has_poc': has_poc
        }
    
    # 共享组件 → 潜在可行
    if component_type == 'shared':
        return {
            'level': 'Potential',
            'label': 'POTENTIAL',
            'order': 2,
            'reason': 'Shared component, could affect Electron/CEF',
            'has_poc': has_poc
        }
    
    # 未知组件
    return {
        'level': 'Unknown',
        'label': 'UNKNOWN',
        'order': 1,
        'reason': 'Unable to determine component scope',
        'has_poc': has_poc
    }


def build_risk_report():
    print("Loading data sources...")
    
    releases = load_json('data/releases.json')
    chromium_cves = load_json('data/chromium-cves.json')
    kev = load_json('data/kev.json')
    version_history = load_json('data/version-history.json')
    gerrit_cache = load_json('data/gerrit-cache.json')
    
    # 加载 exploit 情报数据库（已验证/已测试的 exploit 信息）
    exploit_intel_data = load_json('data/exploit-intel.json')
    exploit_intel_by_cve = {}
    if isinstance(exploit_intel_data, list):
        for ei in exploit_intel_data:
            exploit_intel_by_cve[ei['cve_id']] = ei
    print(f"  Exploit intel: {len(exploit_intel_by_cve)} entries")
    
    cves = chromium_cves.get('cves', [])
    kev_list = kev.get('kev', [])
    releases_list = releases.get('releases', [])
    
    print(f"  Releases: {len(releases_list)}")
    print(f"  CVEs: {len(cves)}")
    print(f"  KEVs: {len(kev_list)}")
    print(f"  Gerrit cache: {len(gerrit_cache)} entries")
    
    # KEV 索引
    kev_index = {k['cve_id']: k for k in kev_list}
    
    # Releases 索引
    releases_by_cve = {}
    for release in releases_list:
        for cve_id in release.get('cves', []):
            releases_by_cve.setdefault(cve_id, []).append(release)
    
    # 关联数据
    print("\nCorrelating data...")
    gerrit_count = 0
    
    for cve in cves:
        cve_id = cve['id']
        
        # KEV
        kev_entry = kev_index.get(cve_id)
        if kev_entry:
            cve['in_kev'] = True
            cve['kev_date'] = kev_entry.get('date_added', '')
            cve['kev_desc'] = kev_entry.get('short_description', '')
        else:
            cve['in_kev'] = False
        
        # Releases
        release_info = releases_by_cve.get(cve_id, [])
        if release_info:
            cve['in_the_wild'] = release_info[0].get('in_the_wild', False)
            if not cve.get('blog_url'):
                cve['blog_url'] = release_info[0].get('url', '')
        else:
            cve['in_the_wild'] = False
        
        # Tracking URLs
        bug_id = cve.get('bug_id')
        if bug_id:
            cve['bug_url'] = f'https://crbug.com/{bug_id}'
        
        # Gerrit from cache
        if bug_id and bug_id in gerrit_cache and gerrit_cache[bug_id]:
            gerrit = gerrit_cache[bug_id]
            if gerrit.get('gerrit_url'):
                cve['gerrit_url'] = gerrit['gerrit_url']
                cve['gerrit_subject'] = gerrit.get('subject', '')
                gerrit_count += 1
        
        # 组件分析
        comp, comp_type = extract_component(cve.get('description', ''))
        cve['component'] = comp
        cve['component_type'] = comp_type
        
        # 自动设置版本追踪粒度（基于组件类型）
        if comp_type == 'shared' and comp in COMPONENT_GRANULARITY:
            cve['version_granularity'] = COMPONENT_GRANULARITY[comp]['granularity']
            cve['granularity_note'] = COMPONENT_GRANULARITY[comp]['note']
        else:
            cve['version_granularity'] = DEFAULT_GRANULARITY
        
        # Exploit 性评估
        cve['exploitability'] = assess_exploitability(cve)
        
        # 合并 exploit 情报：已验证的 exploit 数据
        ei = exploit_intel_by_cve.get(cve_id)
        if ei:
            cve['exploit_intel'] = {
                'version_granularity': ei.get('version_granularity', 'chromium'),
                'exploit_status': ei.get('exploit_status', {}),
                'v8_exploit_range': ei.get('v8_exploit_range', {}),
                'exploit_chain': ei.get('exploit_chain', {}),
                'tested_apps': ei.get('tested_apps', []),
                'key_findings': ei.get('key_findings', []),
            }
            # 提升 exploitability 级别（如有验证数据）
            if ei.get('exploit_status', {}).get('level') == 'VERIFIED_PARTIAL':
                cve['exploitability']['verified_exploit'] = True
                cve['exploitability']['v8_note'] = 'Exploit verified on V8 13.9 d8; V8 13.4 does not trigger same SSE behavior'
    
    print(f"  Enriched {gerrit_count} CVEs with Gerrit links")
    
    # Sort by exploitability order descending, then by recency
    cves.sort(key=lambda x: (
        -x.get('exploitability', {}).get('order', 0),
        x.get('id', '')
    ))
    
    # Strip noise: remove empty/null fields to reduce file size
    for cve in cves:
        for key in list(cve.keys()):
            if cve[key] is None or cve[key] == '' or cve[key] == [] or cve[key] == 0:
                if key not in ('cvss', 'risk_score', 'version_granularity', 'granularity_note'):
                    del cve[key]
    
    # Summary
    summary = {
        'total_cves': len(cves),
        'in_kev': sum(1 for c in cves if c.get('in_kev')),
        'in_the_wild': sum(1 for c in cves if c.get('in_the_wild')),
        'has_public_exploit': sum(1 for c in cves if c.get('has_public_exploit')),
        'has_exploit_intel': sum(1 for c in cves if c.get('exploit_intel')),
        'exploit_verified': sum(1 for c in cves if c.get('exploitability', {}).get('verified_exploit')),
        'by_exploitability': {},
        'by_component': {},
        'shared_components': sum(1 for c in cves if c.get('component_type') == 'shared'),
        'chrome_specific': sum(1 for c in cves if c.get('component_type') == 'chrome'),
    }
    
    for cve in cves:
        level = cve.get('exploitability', {}).get('level', 'Unknown')
        comp = cve.get('component', 'Unknown')
        gran = cve.get('version_granularity', 'chromium')
        summary['by_exploitability'][level] = summary['by_exploitability'].get(level, 0) + 1
        summary['by_component'][comp] = summary['by_component'].get(comp, 0) + 1
        summary['by_granularity'] = summary.get('by_granularity', {})
        summary['by_granularity'][gran] = summary['by_granularity'].get(gran, 0) + 1
    
    # Save - compact format for smaller file size
    output_dir = Path('data')
    output_dir.mkdir(exist_ok=True)
    
    report = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'summary': summary,
        'cves': cves,
    }
    
    output_file = output_dir / 'risk-report.json'
    output_file.write_text(json.dumps(report, indent=None, ensure_ascii=False, separators=(',', ':')))
    
    print(f"\nSaved {len(cves)} CVEs to {output_file}")
    print(f"\nExploitability for Electron/CEF:")
    for level in ['Confirmed', 'High', 'Likely', 'Potential', 'Not Applicable', 'Unknown']:
        count = summary['by_exploitability'].get(level, 0)
        if count:
            print(f"  {level:25s}: {count}")
    print(f"  {'Public PoC/Exploit':25s}: {summary['has_public_exploit']}")
    print(f"  {'Exploit Intel entries':25s}: {summary.get('has_exploit_intel', 0)}")
    print(f"  {'Exploit verified':25s}: {summary.get('exploit_verified', 0)}")
    print(f"\nTop Components (shared vs chrome-only):")
    print(f"  Shared components: {summary['shared_components']}")
    print(f"  Chrome-specific:   {summary['chrome_specific']}")
    print(f"\nVersion granularity:")
    by_gran = summary.get('by_granularity', {})
    for gran in sorted(by_gran.keys()):
        print(f"  {gran:20s}: {by_gran[gran]}")
    
    return report


def main():
    return build_risk_report()


if __name__ == '__main__':
    main()
