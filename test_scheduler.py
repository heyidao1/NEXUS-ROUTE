# -*- coding: utf-8 -*-
"""
NEXUS-ROUTE Ingestion & Concurrency Test Suite (v3.0.0-PRO)
Verifies contract validation limits and lock-free disruptor safety.
Path: B:\NEXUS_ROUTE\test_scheduler.py
"""

import pytest
import threading
import concurrent.futures
from pydantic import ValidationError
from config_refined import RefinedOrderPacket
from main import DisruptorRingBuffer, DeepSeekHealerAgent

# ==============================================================================
# 1. DATA CONTRACT VALIDATION TESTS (契约层边界测试)
# ==============================================================================
def test_contract_valid_payload():
    """
    验证标准合法载荷，确保 LC_ 绿春合作社等标准前缀及正数重量通过校验。
    """
    payload = {
        "client_id": "LC_AGRICULTURE_COOP_2026",
        "sku_list": ["RED_TEA_01", "GREEN_TEA_02"],
        "total_weight": 142.50,
        "dispatch_priority": 2
    }
    packet = RefinedOrderPacket(**payload)
    assert packet.client_id == "LC_AGRICULTURE_COOP_2026"
    assert packet.total_weight == 142.50
    assert packet.dispatch_priority == 2


def test_contract_invalid_prefix():
    """
    验证非法 client_id 前缀拦截，必须抛出 ValueError / ValidationError。
    """
    with pytest.raises(ValidationError) as excinfo:
        RefinedOrderPacket(
            client_id="INVALID_PREFIX_991",
            sku_list=["TEST_SKU"],
            total_weight=50.0
        )
    assert "CRITICAL_SCHEMA_BREACH" in str(excinfo.value)


def test_contract_invalid_weight():
    """
    验证负数及零重量拦截，确保不允许物理载荷小于等于 0。
    """
    with pytest.raises(ValidationError) as excinfo:
        RefinedOrderPacket(
            client_id="LC_COOP_01",
            sku_list=["TEST_SKU"],
            total_weight=0.0
        )
    assert "Consolidated transaction cargo weight must exceed 0.0 kg" in str(excinfo.value)


# ==============================================================================
# 2. LOCK-FREE CONCURRENCY TESTS (并发层无锁竞态测试)
# ==============================================================================
def test_ring_buffer_concurrency_safety():
    """
    多线程高并发高频注入无锁环形缓冲区，验证 CAS 序列指针安全，无丢包、无竞态冲突。
    """
    capacity = 500
    ring_buffer = DisruptorRingBuffer(capacity=capacity)
    thread_count = 16
    pushes_per_thread = 20
    
    packet = RefinedOrderPacket(
        client_id="LC_AGRICULTURE_COOP_2026",
        sku_list=["CONCURRENT_SKU"],
        total_weight=10.0
    )

    def worker():
        for _ in range(pushes_per_thread):
            ring_buffer.publish(packet)

    # 启动 16 个线程并行灌入数据
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # 验证消费端完整提取，数据结构无坍塌
    consumed_count = 0
    while True:
        p = ring_buffer.consume()
        if p is None:
            break
        consumed_count += 1

    assert consumed_count == (thread_count * pushes_per_thread)


# ==============================================================================
# 3. DYNAMIC HEALER AGENT INTEGRATION TESTS (动态自愈链路测试)
# ==============================================================================
def test_healer_agent_hot_patching():
    """
    模拟运行时异常阻断，验证 Healer Agent 是否能成功提取 Traceback 
    并将 '绿春' 精准热修复为合规的 'LC_AGRICULTURE_COOP_2026'。
    """
    raw_payload = {
        "client_id": "绿春",
        "sku_list": ["HEALED_SKU"],
        "total_weight": 88.5
    }

    try:
        # Pydantic 强契约层应当拦截
        RefinedOrderPacket(**raw_payload)
        pytest.fail("Should have triggered validation error for client_id='绿春'")
    except ValidationError as ve:
        # 激活 Healer Agent 虚拟时间线自愈
        mock_anchor_time = 1779870959.0 # 对齐 2026-05-26 21:55:59 时间戳
        healed_client_id = DeepSeekHealerAgent.compile_heap_patch("绿春", ve, mock_anchor_time)
        
        # 验证热补丁纠正结果
        assert healed_client_id == "LC_AGRICULTURE_COOP_2026"
        
        # 使用补丁重建，保证过账成功
        raw_payload["client_id"] = healed_client_id
        healed_packet = RefinedOrderPacket(**raw_payload)
        assert healed_packet.client_id == "LC_AGRICULTURE_COOP_2026"
