# ========== 新增调试：检查节点名称与地区组名的冲突 ==========
print("\n[DEBUG] Checking for node names that conflict with region group names:")
ctg_disp_values = set(snip_conf['categories_disp'].values()) if snip_conf else set()
conflicting_node_names = {}
for hashp, node in merged.items():
    node_name = node.data['name']
    if node_name in ctg_disp_values:
        src_ids = used.get(hashp, {})
        src_names = [sources_obj[sid].url for sid in src_ids if sid in sources_obj]
        conflicting_node_names[node_name] = src_names
if conflicting_node_names:
    print("  ⚠️⚠️ Found node names that match region group names:")
    for name, srcs in conflicting_node_names.items():
        print(f"    '{name}' from sources: {srcs}")
else:
    print("  ✅ No node names conflict with region group names.")
# ===========================================================
