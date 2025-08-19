import math
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import json

try:
    from .config import ConfigManager
except ImportError:
    from config import ConfigManager


@dataclass
class HexViewAnnotation:
    """𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯 𐑓𐑹 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑚𐑲𐑑 𐑮𐑱𐑯𐑡 𐑦𐑯 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿"""
    start_offset: int
    end_offset: int
    annotation_type: str  # 'suggestion', 'analysis', 'section', 'string', 'entropy'
    title: str
    description: str
    severity: str = "info"  # 'info', 'warning', 'danger', 'success'
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class HexViewer:
    """𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑣𐑧𐑒𐑕 𐑛𐑳𐑥𐑐 𐑝𐑿𐑼 𐑢𐑦𐑞 𐑨𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑴𐑝𐑼𐑤𐑱"""
    
    def __init__(self, config: ConfigManager = None, base_offset: int = 0):
        """𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼"""
        self.config = config
        self.annotations: List[HexViewAnnotation] = []
        self.binary_data: bytes = b''
        self.bytes_per_row = 16
        self.show_ascii = True
        self.show_offsets = True
        self.base_offset = base_offset  # 𐑚𐑱𐑕 𐑪𐑓𐑕𐑧𐑑 𐑓𐑹 𐑛𐑦𐑕𐑐𐑤𐑱
        
    def load_binary_data(self, data: bytes):
        """𐑤𐑴𐑛 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩 𐑦𐑯𐑑 𐑞 𐑝𐑿𐑼"""
        self.binary_data = data
        
    def add_annotation(self, annotation: HexViewAnnotation):
        """𐑨𐑛 𐑩 𐑯𐑿 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯 𐑑 𐑞 𐑝𐑿𐑼"""
        self.annotations.append(annotation)
        
    def add_section_annotations(self, sections: List[Dict[str, Any]]):
        """𐑨𐑛 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑓𐑹 𐑚𐑲𐑯𐑩𐑮𐑦 𐑕𐑧𐑒𐑖𐑩𐑯𐑟"""
        for section in sections:
            if hasattr(section, 'name') and hasattr(section, 'size'):
                # 𐑿𐑟 𐑓𐑲𐑤 𐑪𐑓𐑕𐑧𐑑 𐑦𐑓 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤, 𐑷𐑞𐑼𐑢𐑲𐑟 𐑓𐑷𐑤 𐑚𐑨𐑒 𐑑 𐑝𐑻𐑗𐑫𐑩𐑤 𐑨𐑛𐑮𐑧𐑕
                file_offset = getattr(section, 'offset', getattr(section, 'virtual_address', 0))
                section_size = section.size
                
                annotation = HexViewAnnotation(
                    start_offset=file_offset,
                    end_offset=file_offset + section_size,
                    annotation_type="section",
                    title=f"Section: {section.name}",
                    description=f"Size: {section_size} bytes, FileOffset: 0x{file_offset:08x}, VAddr: 0x{getattr(section, 'virtual_address', 0):08x}",
                    severity="info",
                    metadata={
                        "section_name": section.name,
                        "file_offset": file_offset,
                        "virtual_address": getattr(section, 'virtual_address', 0),
                        "size": section_size,
                        "characteristics": getattr(section, 'characteristics', None)
                    }
                )
                self.add_annotation(annotation)
                
    def add_analysis_annotations(self, analysis_results: Dict[str, Any]):
        """𐑨𐑛 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑓𐑮𐑩𐑥 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑮𐑦𐑟𐑳𐑤𐑑𐑟"""
        # 𐑨𐑛 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑨𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟
        if 'entropy_analysis' in analysis_results:
            entropy_data = analysis_results['entropy_analysis']
            if isinstance(entropy_data, dict) and 'high_entropy_regions' in entropy_data:
                for region in entropy_data['high_entropy_regions']:
                    severity = "danger" if region.get('entropy', 0) > 7.5 else "warning"
                    annotation = HexViewAnnotation(
                        start_offset=region.get('offset', 0),
                        end_offset=region.get('offset', 0) + region.get('size', 0),
                        annotation_type="entropy",
                        title=f"High Entropy Region (Score: {region.get('entropy', 0):.2f})",
                        description=f"Potentially packed/encrypted data. Entropy: {region.get('entropy', 0):.2f}",
                        severity=severity,
                        metadata=region
                    )
                    self.add_annotation(annotation)
                    
        # 𐑨𐑛 𐑕𐑑𐑮𐑦𐑙 𐑦𐑒𐑕𐑑𐑮𐑨𐑒𐑖𐑩𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟
        if 'string_extraction' in analysis_results:
            string_data = analysis_results['string_extraction']
            if isinstance(string_data, dict) and 'extracted_strings' in string_data:
                for string_info in string_data['extracted_strings'][:50]:  # 𐑤𐑦𐑥𐑦𐑑 𐑑 50 𐑕𐑑𐑮𐑦𐑙𐑟
                    annotation = HexViewAnnotation(
                        start_offset=string_info.get('offset', 0),
                        end_offset=string_info.get('offset', 0) + len(string_info.get('value', '')),
                        annotation_type="string",
                        title=f"String: {string_info.get('value', '')[:30]}{'...' if len(string_info.get('value', '')) > 30 else ''}",
                        description=f"String found: '{string_info.get('value', '')}' (Type: {string_info.get('type', 'unknown')})",
                        severity="info",
                        metadata=string_info
                    )
                    self.add_annotation(annotation)
                    
    def add_suggestion_annotations(self, suggestions: List[Dict[str, Any]]):
        """𐑨𐑛 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑓𐑹 𐑪𐑚𐑓𐑳𐑕𐑒𐑱𐑖𐑩𐑯 𐑕𐑩𐑜𐑧𐑕𐑑𐑑𐑩𐑯𐑟"""
        for suggestion in suggestions:
            if 'section' in suggestion and 'tier' in suggestion:
                severity_map = {
                    'green': 'success',
                    'yellow': 'warning', 
                    'blue': 'info',
                    'red': 'danger'
                }
                severity = severity_map.get(suggestion['tier'].lower(), 'info')
                
                annotation = HexViewAnnotation(
                    start_offset=suggestion.get('offset', 0),
                    end_offset=suggestion.get('offset', 0) + suggestion.get('size', 0),
                    annotation_type="suggestion",
                    title=f"Encoding Suggestion: {suggestion['section']} ({suggestion['tier'].upper()})",
                    description=f"Tier: {suggestion['tier']} - {suggestion.get('reason', 'No reason provided')}",
                    severity=severity,
                    metadata=suggestion
                )
                self.add_annotation(annotation)
                
    def generate_html_hex_view(self, max_bytes: int = 2048) -> str:
        """𐑡𐑧𐑯𐑼𐑱𐑑 HTML 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑣𐑧𐑒𐑕 𐑝𐑿"""
        if not self.binary_data:
            return "<p>𐑯𐑴 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩 𐑤𐑴𐑛𐑦𐑛</p>"
            
        # 𐑤𐑦𐑥𐑦𐑑 𐑛𐑱𐑑𐑩 𐑓𐑹 𐑐𐑼𐑓𐑹𐑥𐑩𐑯𐑕
        data_to_show = self.binary_data[:max_bytes]
        total_rows = math.ceil(len(data_to_show) / self.bytes_per_row)
        
        html = f"""
        <div class="hex-viewer">
            <div class="hex-viewer-header">
                <h3>🔍 Interactive Hex View</h3>
                <div class="hex-controls">
                    <span class="hex-info">Showing {len(data_to_show)} of {len(self.binary_data)} bytes</span>
                    <span class="hex-info">{len(self.annotations)} annotations</span>
                </div>
            </div>
            <div class="hex-container">
                <div class="hex-content">
        """
        
        # 𐑡𐑧𐑯𐑼𐑱𐑑 𐑣𐑧𐑒𐑕 𐑮𐑴𐑟
        for row in range(total_rows):
            start_offset = row * self.bytes_per_row
            end_offset = min(start_offset + self.bytes_per_row, len(data_to_show))
            row_data = data_to_show[start_offset:end_offset]
            
            html += self._generate_hex_row(start_offset, row_data)
            
        html += """
                </div>
            </div>
            <div class="annotation-tooltip" id="annotationTooltip"></div>
        </div>
        """
        
        return html
        
    def _generate_hex_row(self, offset: int, row_data: bytes) -> str:
        """𐑡𐑧𐑯𐑼𐑱𐑑 𐑩 𐑕𐑦𐑙𐑜𐑩𐑤 𐑣𐑧𐑒𐑕 𐑮𐑴"""
        hex_cells = []
        ascii_cells = []
        
        for i, byte_val in enumerate(row_data):
            byte_offset = offset + i
            display_offset = self.base_offset + byte_offset  # 𐑨𐑒𐑗𐑫𐑩𐑤 𐑪𐑓𐑕𐑧𐑑 𐑦𐑯 𐑞 𐑓𐑲𐑤
            annotations = self._get_annotations_for_offset(display_offset)
            
            # 𐑒𐑮𐑦𐑱𐑑 CSS 𐑒𐑤𐑭𐑕 𐑚𐑱𐑕𐑑 𐑪𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟
            css_classes = ["hex-byte"]
            if annotations:
                css_classes.append("annotated")
                for ann in annotations:
                    css_classes.append(f"severity-{ann.severity}")
                    css_classes.append(f"type-{ann.annotation_type}")
            
            annotations_json = json.dumps([{
                'title': ann.title,
                'description': ann.description,
                'type': ann.annotation_type,
                'severity': ann.severity,
                'metadata': ann.metadata
            } for ann in annotations])
            
            class_string = " ".join(css_classes)
            escaped_annotations = annotations_json.replace('"', '&quot;')
            hex_cell = f'<span class="{class_string}" data-offset="{display_offset}" data-annotations="{escaped_annotations}">{byte_val:02x}</span>'
            hex_cells.append(hex_cell)
            
            # ASCII 𐑮𐑦𐑐𐑮𐑦𐑟𐑧𐑯𐑑𐑱𐑖𐑩𐑯
            if 32 <= byte_val <= 126:
                ascii_char = chr(byte_val)
            else:
                ascii_char = "."
                
            ascii_cell = f'<span class="{class_string}" data-offset="{display_offset}" data-annotations="{escaped_annotations}">{ascii_char}</span>'
            ascii_cells.append(ascii_cell)
            
        # 𐑐𐑨𐑛 𐑦𐑯𐑒𐑩𐑥𐑐𐑤𐑰𐑑 𐑮𐑴𐑟
        while len(hex_cells) < self.bytes_per_row:
            hex_cells.append('<span class="hex-byte empty">  </span>')
            ascii_cells.append('<span class="hex-byte empty"> </span>')
            
        display_row_offset = self.base_offset + offset
        offset_str = f"{display_row_offset:08x}" if self.show_offsets else ""
        hex_str = " ".join(hex_cells)
        ascii_str = "".join(ascii_cells) if self.show_ascii else ""
        
        return f"""
        <div class="hex-row">
            <span class="hex-offset">{offset_str}</span>
            <span class="hex-data">{hex_str}</span>
            <span class="hex-ascii">{ascii_str}</span>
        </div>
        """
        
    def _get_annotations_for_offset(self, offset: int) -> List[HexViewAnnotation]:
        """𐑜𐑧𐑑 𐑷𐑤 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑞𐑨𐑑 𐑨𐑐𐑤𐑲 𐑑 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑪𐑓𐑕𐑧𐑑"""
        return [ann for ann in self.annotations 
                if ann.start_offset <= offset < ann.end_offset]
                
    def get_css_styles(self) -> str:
        """𐑜𐑧𐑑 CSS 𐑕𐑑𐑲𐑤𐑟 𐑓𐑹 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼"""
        return """
        .hex-viewer {
            border: 1px solid #ddd;
            border-radius: 8px;
            margin: 20px 0;
            background: #fff;
            font-family: 'Courier New', Consolas, monospace;
        }
        
        .hex-viewer-header {
            background: #f8f9fa;
            padding: 10px 15px;
            border-bottom: 1px solid #ddd;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .hex-viewer-header h3 {
            margin: 0;
            color: #333;
        }
        
        .hex-controls {
            display: flex;
            gap: 15px;
        }
        
        .hex-info {
            font-size: 12px;
            color: #666;
            background: #e9ecef;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .hex-container {
            max-height: 600px;
            overflow-y: auto;
            padding: 10px;
        }
        
        .hex-content {
            font-size: 13px;
            line-height: 1.4;
        }
        
        .hex-row {
            display: flex;
            margin-bottom: 2px;
            align-items: center;
        }
        
        .hex-offset {
            color: #666;
            margin-right: 15px;
            min-width: 80px;
            font-weight: bold;
        }
        
        .hex-data {
            margin-right: 15px;
            min-width: 400px;
        }
        
        .hex-ascii {
            color: #333;
            background: #f8f9fa;
            padding: 0 5px;
            border-radius: 3px;
        }
        
        .hex-byte {
            cursor: pointer;
            padding: 1px 2px;
            border-radius: 2px;
            transition: all 0.2s ease;
        }
        
        .hex-byte:hover {
            background: #e3f2fd;
            transform: scale(1.1);
        }
        
        .hex-byte.annotated {
            position: relative;
            font-weight: bold;
        }
        
        .hex-byte.severity-info {
            background-color: #e3f2fd;
            color: #1976d2;
        }
        
        .hex-byte.severity-success {
            background-color: #e8f5e8;
            color: #2e7d32;
        }
        
        .hex-byte.severity-warning {
            background-color: #fff3cd;
            color: #d68910;
        }
        
        .hex-byte.severity-danger {
            background-color: #f8d7da;
            color: #dc3545;
        }
        
        .hex-byte.type-section {
            border-bottom: 2px solid #1976d2;
        }
        
        .hex-byte.type-string {
            border-bottom: 2px solid #2e7d32;
        }
        
        .hex-byte.type-entropy {
            border-bottom: 2px solid #d68910;
        }
        
        .hex-byte.type-suggestion {
            border-bottom: 2px solid #dc3545;
        }
        
        .hex-byte.empty {
            color: #ccc;
            cursor: default;
        }
        
        .annotation-tooltip {
            position: absolute;
            background: #333;
            color: white;
            padding: 10px;
            border-radius: 6px;
            font-size: 12px;
            max-width: 300px;
            z-index: 1000;
            display: none;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .annotation-tooltip .tooltip-title {
            font-weight: bold;
            margin-bottom: 5px;
            color: #fff;
        }
        
        .annotation-tooltip .tooltip-description {
            margin-bottom: 5px;
            line-height: 1.3;
        }
        
        .annotation-tooltip .tooltip-metadata {
            font-size: 10px;
            color: #ccc;
            border-top: 1px solid #555;
            padding-top: 5px;
            margin-top: 5px;
        }
        """
        
    def get_javascript(self) -> str:
        """𐑜𐑧𐑑 JavaScript 𐑓𐑹 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑓𐑳𐑙𐑒𐑖𐑩𐑯𐑨𐑤𐑦𐑑𐑦"""
        return """
        document.addEventListener('DOMContentLoaded', function() {
            const tooltip = document.getElementById('annotationTooltip');
            const hexBytes = document.querySelectorAll('.hex-byte.annotated');
            
            hexBytes.forEach(function(hexByte) {
                hexByte.addEventListener('mouseenter', function(e) {
                    const annotations = JSON.parse(e.target.getAttribute('data-annotations') || '[]');
                    if (annotations.length > 0) {
                        showTooltip(e, annotations);
                    }
                });
                
                hexByte.addEventListener('mouseleave', function() {
                    hideTooltip();
                });
                
                hexByte.addEventListener('mousemove', function(e) {
                    updateTooltipPosition(e);
                });
            });
            
            function showTooltip(event, annotations) {
                let content = '';
                
                annotations.forEach(function(ann, index) {
                    if (index > 0) content += '<hr style="margin: 8px 0; border-color: #555;">';
                    
                    content += '<div class="tooltip-title">' + escapeHtml(ann.title) + '</div>';
                    content += '<div class="tooltip-description">' + escapeHtml(ann.description) + '</div>';
                    
                    if (ann.metadata && Object.keys(ann.metadata).length > 0) {
                        content += '<div class="tooltip-metadata">';
                        content += 'Type: ' + escapeHtml(ann.type) + '<br>';
                        content += 'Severity: ' + escapeHtml(ann.severity) + '<br>';
                        
                        // 𐑕𐑴 𐑦𐑯𐑑𐑼𐑧𐑕𐑑𐑦𐑙 𐑥𐑧𐑑𐑩𐑛𐑱𐑑𐑩
                        for (const [key, value] of Object.entries(ann.metadata)) {
                            if (key !== 'type' && key !== 'severity' && value !== null && value !== undefined) {
                                content += escapeHtml(key) + ': ' + escapeHtml(String(value)) + '<br>';
                            }
                        }
                        content += '</div>';
                    }
                });
                
                tooltip.innerHTML = content;
                tooltip.style.display = 'block';
                updateTooltipPosition(event);
            }
            
            function hideTooltip() {
                tooltip.style.display = 'none';
            }
            
            function updateTooltipPosition(event) {
                const x = event.pageX + 10;
                const y = event.pageY + 10;
                
                tooltip.style.left = x + 'px';
                tooltip.style.top = y + 'px';
                
                // 𐑩𐑡𐑳𐑕𐑑 𐑦𐑓 𐑑𐑵𐑤𐑑𐑦𐑐 𐑣𐑦𐑑𐑟 𐑞 𐑧𐑡 𐑝 𐑞 𐑢𐑦𐑯𐑛𐑴
                const rect = tooltip.getBoundingClientRect();
                if (rect.right > window.innerWidth) {
                    tooltip.style.left = (event.pageX - rect.width - 10) + 'px';
                }
                if (rect.bottom > window.innerHeight) {
                    tooltip.style.top = (event.pageY - rect.height - 10) + 'px';
                }
            }
            
            function escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }
        });
        """