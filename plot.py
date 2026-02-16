#!/usr/bin/env python3
import json, glob, collections, os
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

plt.rcParams['font.family'] = 'WenQuanYi Micro Hei'  # 设置中文字体，确保支持中文显示

GUA_NAMES = {
    0: "KUN", 1: "ZHEN", 2: "KAN", 3: "DUI",
    4: "GEN", 5: "LI", 6: "XUN", 7: "QIAN"
}

ELEMENT_NAMES = {
    0: "木(Wood)", 1: "火(Fire)", 2: "土(Earth)", 3: "金(Metal)", 4: "水(Water)"
}

def load(path):
    with open(path, "r") as f:
        return json.load(f)

def extract_records(data):
    """统一提取记录"""
    if isinstance(data, dict) and "tasks" in data:
        return data["tasks"], data.get("timestamp", 0)
    return data, 0

files = sorted(glob.glob("./scx/task_ctx_*.json"))
if not files:
    raise SystemExit("no samples found in ./scx/task_ctx_*.json")

os.makedirs("./scx", exist_ok=True)

# === 快照分析（最后一次采样）===
data = load(files[-1])
records, ts = extract_records(data)

gua_cnt = collections.Counter()
cpu_cnt = collections.Counter()
element_cnt = collections.Counter()
gua_cpu_matrix = collections.defaultdict(lambda: collections.Counter())

for item in records:
    if isinstance(item, dict) and "value" in item:
        v = item.get("value", {})
    else:
        v = item
    if not isinstance(v, dict):
        continue
    gua = v.get("current_gua", 0)
    cpu = v.get("assigned_cpu", 0)
    elem = v.get("current_element", 0)
    gua_cnt[gua] += 1
    cpu_cnt[cpu] += 1
    element_cnt[elem] += 1
    gua_cpu_matrix[gua][cpu] += 1

# 图1: 卦象分布（柱状图）
fig, ax = plt.subplots(figsize=(10, 5))
labels = [GUA_NAMES[i] for i in range(8)]
values = [gua_cnt.get(i, 0) for i in range(8)]
colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', 
          '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2']
ax.bar(labels, values, color=colors)
ax.set_title("八卦分布 (Gua Distribution - Last Snapshot)", fontsize=14, fontweight='bold')
ax.set_ylabel("Task Count")
for i, v in enumerate(values):
    ax.text(i, v + 0.5, str(v), ha='center', fontweight='bold')
fig.tight_layout()
fig.savefig("./scx/01_gua_dist.png", dpi=120)
plt.close(fig)

# 图2: CPU 分配分布
fig, ax = plt.subplots(figsize=(10, 5))
cpus = sorted(cpu_cnt.keys())
vals = [cpu_cnt[c] for c in cpus]
ax.bar([f"CPU{c}" for c in cpus], vals, color='#3498db')
ax.set_title("CPU分配分布 (CPU Distribution)", fontsize=14, fontweight='bold')
ax.set_ylabel("Task Count")
for i, v in enumerate(vals):
    ax.text(i, v + 0.5, str(v), ha='center', fontweight='bold')
fig.tight_layout()
fig.savefig("./scx/02_cpu_dist.png", dpi=120)
plt.close(fig)

# 图3: 五行元素分布（饼图）
fig, ax = plt.subplots(figsize=(8, 8))
elem_labels = [ELEMENT_NAMES.get(i, f"Unknown{i}") for i in range(5)]
elem_values = [element_cnt.get(i, 0) for i in range(5)]
# 过滤掉0的元素
non_zero = [(l, v) for l, v in zip(elem_labels, elem_values) if v > 0]
if non_zero:
    labels, values = zip(*non_zero)
    colors_pie = ['#2ecc71', '#e74c3c', '#f39c12', '#9b59b6', '#1abc9c']
    ax.pie(values, labels=labels, autopct='%1.1f%%', colors=colors_pie[:len(labels)],
           startangle=90)
    ax.set_title("五行元素分布 (Elements Distribution)", fontsize=14, fontweight='bold')
else:
    ax.text(0.5, 0.5, "No data", ha='center', va='center')
fig.tight_layout()
fig.savefig("./scx/03_element_pie.png", dpi=120)
plt.close(fig)

# 图4: 卦象-CPU 映射热力图
fig, ax = plt.subplots(figsize=(15, 6))
gua_list = list(range(8))
cpu_list = sorted(set(cpus))
matrix = np.zeros((len(gua_list), len(cpu_list)))
for i, gua in enumerate(gua_list):
    for j, cpu in enumerate(cpu_list):
        matrix[i, j] = gua_cpu_matrix[gua].get(cpu, 0)

im = ax.imshow(matrix, cmap='YlOrRd', aspect='auto')
ax.set_xticks(range(len(cpu_list)))
ax.set_yticks(range(len(gua_list)))
ax.set_xticklabels([f"{c}" for c in cpu_list])
ax.set_yticklabels([GUA_NAMES[g] for g in gua_list])
ax.set_title("卦象-CPU 映射热力图 (Gua-CPU Heatmap)", fontsize=14, fontweight='bold')
ax.set_xlabel("CPU")
ax.set_ylabel("Gua")

# 添加数值标注
for i in range(len(gua_list)):
    for j in range(len(cpu_list)):
        text = ax.text(j, i, int(matrix[i, j]),
                      ha="center", va="center", color="black", fontweight='bold')

fig.colorbar(im, ax=ax, label='Task Count')
fig.tight_layout()
fig.savefig("./scx/04_gua_cpu_heatmap.png", dpi=120)
plt.close(fig)

# === 时间序列分析 ===
if len(files) > 1:
    timeline = []
    gua_timeline = {i: [] for i in range(8)}
    cpu_timeline = {i: [] for i in range(max(cpus) + 1) if i in cpus}
    
    for fpath in files:
        try:
            fdata = load(fpath)
            frecs, fts = extract_records(fdata)
            
            # 提取时间戳从文件名或数据
            fname = os.path.basename(fpath)
            try:
                ts_from_name = int(fname.split('_')[2].split('.')[0])
            except:
                ts_from_name = fts
            
            timeline.append(ts_from_name)
            
            # 统计本次快照的卦象和CPU分布
            snap_gua = collections.Counter()
            snap_cpu = collections.Counter()
            for rec in frecs:
                if isinstance(rec, dict) and "value" in rec:
                    rec = rec["value"]
                if not isinstance(rec, dict):
                    continue
                snap_gua[rec.get("current_gua", 0)] += 1
                snap_cpu[rec.get("assigned_cpu", 0)] += 1
            
            for i in range(8):
                gua_timeline[i].append(snap_gua.get(i, 0))
            for cpu in cpu_timeline:
                cpu_timeline[cpu].append(snap_cpu.get(cpu, 0))
        except Exception as e:
            print(f"Warning: skip {fpath}: {e}")
            continue
    
    if len(timeline) > 1:
        # 图5: 卦象时间序列
        fig, ax = plt.subplots(figsize=(12, 6))
        for gua in range(8):
            ax.plot(range(len(timeline)), gua_timeline[gua], marker='o', 
                   label=GUA_NAMES[gua], linewidth=2)
        ax.set_title("八卦分布时间序列 (Gua Timeline)", fontsize=14, fontweight='bold')
        ax.set_xlabel("Sample Index")
        ax.set_ylabel("Task Count")
        ax.legend(loc='upper left', ncol=2)
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig("./scx/05_gua_timeline.png", dpi=120)
        plt.close(fig)
        
        # 图6: CPU分布时间序列
        fig, ax = plt.subplots(figsize=(12, 6))
        for cpu in sorted(cpu_timeline.keys()):
            ax.plot(range(len(timeline)), cpu_timeline[cpu], marker='s', 
                   label=f"CPU{cpu}", linewidth=2)
        ax.set_title("CPU分布时间序列 (CPU Timeline)", fontsize=14, fontweight='bold')
        ax.set_xlabel("Sample Index")
        ax.set_ylabel("Task Count")
        ax.legend(loc='upper left', ncol=2)
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig("./scx/06_cpu_timeline.png", dpi=120)
        plt.close(fig)

print("✓ saved plots to ./scx/")
print("  01_gua_dist.png       - 卦象分布柱状图")
print("  02_cpu_dist.png       - CPU分配分布柱状图")
print("  03_element_pie.png    - 五行元素分布饼图")
print("  04_gua_cpu_heatmap.png - 卦象-CPU映射热力图")
if len(files) > 1:
    print("  05_gua_timeline.png   - 卦象时间序列折线图")
    print("  06_cpu_timeline.png   - CPU分配时间序列折线图")