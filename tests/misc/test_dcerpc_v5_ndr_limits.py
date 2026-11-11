#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest
from struct import pack

from impacket.dcerpc.v5.ndr import (
    NDR,
    NDRCALL,
    NDRLONG,
    NDRULONG,
    NDRSHORT,
    NDRLimitError,
    NDRLimits,
    NDRPOINTER,
    NDRPOINTERNULL,
    NDRSTRUCT,
    NDRUniConformantArray,
    NDRUniConformantVaryingArray,
    NDRUniVaryingArray,
    getDefaultLimits,
    setDefaultLimits,
)


# ---------------------------------------------------------------------------
# Hand-written NDR types used by the tests
# ---------------------------------------------------------------------------
class ByteArray(NDRUniConformantArray):
    item = 'c'


class LongArray(NDRUniConformantArray):
    item = '<L'


class VaryingByteArray(NDRUniVaryingArray):
    item = 'c'


class ConformantVaryingByteArray(NDRUniConformantVaryingArray):
    item = 'c'


class PLong(NDRPOINTER):
    referent = (
        ('Data', NDRULONG),
    )


class PByteArray(NDRPOINTER):
    referent = (
        ('Data', ByteArray),
    )


class Holder(NDRSTRUCT):
    structure = (
        ('First', PLong),
        ('Second', PLong),
    )


class PHolder(NDRPOINTER):
    referent = (
        ('Data', Holder),
    )


class InnerStruct(NDRSTRUCT):
    structure = (
        ('Arr', ByteArray),
    )


class PInnerStruct(NDRPOINTER):
    referent = (
        ('Data', InnerStruct),
    )


class ConformantArrayCall(NDRCALL):
    structure = (
        ('Data', ByteArray),
    )


class LongArrayCall(NDRCALL):
    structure = (
        ('Data', LongArray),
    )


class VaryingArrayCall(NDRCALL):
    structure = (
        ('Data', VaryingByteArray),
    )


class ConformantVaryingArrayCall(NDRCALL):
    structure = (
        ('Data', ConformantVaryingByteArray),
    )


class PrimitiveCall(NDRCALL):
    structure = (
        ('First', NDRULONG),
        ('Second', NDRULONG),
    )


class NullPointerCall(NDRCALL):
    structure = (
        ('Ptr', NDRPOINTERNULL),
    )


class PointerCall(NDRCALL):
    structure = (
        ('Ptr', PLong),
    )


class SharedPointerCall(NDRCALL):
    structure = (
        ('Holder', PHolder),
    )


class NestedArrayCall(NDRCALL):
    structure = (
        ('Inner', PInnerStruct),
    )


class NDRLimitsConstructionTests(unittest.TestCase):

    def test_invalid_limits_are_rejected(self):
        for kwargs in (
            {'max_array_elements': -1},
            {'max_octets': -5},
            {'max_referents': -1},
            {'max_depth': -1},
            {'max_array_elements': 1.5},
            {'max_depth': True},
        ):
            with self.assertRaises(ValueError):
                NDRLimits(**kwargs)

    def test_zero_budgets_are_valid(self):
        # Zero is an allowed (most restrictive) value for every budget.
        limits = NDRLimits(
            max_array_elements=0, max_octets=0, max_referents=0, max_depth=0)
        self.assertEqual(limits.max_depth, 0)

    def test_default_limits_global_switch(self):
        self.assertIsNone(getDefaultLimits())
        limits = NDRLimits()
        setDefaultLimits(limits)
        try:
            self.assertIs(getDefaultLimits(), limits)
        finally:
            setDefaultLimits(None)
        self.assertIsNone(getDefaultLimits())

    def test_set_default_limits_type_check(self):
        with self.assertRaises(TypeError):
            setDefaultLimits(object())

    def test_limits_can_be_reset_and_reused(self):
        limits = NDRLimits(max_array_elements=10)
        ConformantArrayCall(pack('<L', 3) + b'abc', limits=limits)
        self.assertEqual(limits.array_elements, 3)
        limits.reset()
        self.assertEqual(limits.array_elements, 0)
        self.assertEqual(limits.depth, 0)
        ConformantArrayCall(pack('<L', 2) + b'de', limits=limits)
        self.assertEqual(limits.array_elements, 2)


class UnrestrictedCompatibilityTests(unittest.TestCase):
    """Without limits the decoder keeps its historical, lenient behavior."""

    def test_huge_count_is_silently_truncated_without_limits(self):
        evil = pack('<L', 0xFFFFFFFF) + b'ab'
        call = ConformantArrayCall(evil)
        # The legacy decoder stops at end-of-stream instead of raising.
        self.assertEqual(len(call['Data']), 2)
        self.assertIsNone(call.getLimits())

    def test_truncated_primitive_does_not_raise_without_limits(self):
        # struct.error is the pre-existing behavior, not NDRLimitError.
        with self.assertRaises(Exception) as ctx:
            PrimitiveCall(b'\x01\x02')
        self.assertNotIsInstance(ctx.exception, NDRLimitError)

    def test_default_limits_none_means_fully_unrestricted(self):
        setDefaultLimits(None)
        try:
            call = ConformantArrayCall(pack('<L', 0xFFFFFFFF) + b'x')
            self.assertIsNone(call.limits)
        finally:
            setDefaultLimits(None)

    def test_explicit_none_overrides_global_default(self):
        setDefaultLimits(NDRLimits(max_array_elements=1))
        try:
            # Explicit limits=None must restore unrestricted decoding.
            call = ConformantArrayCall(pack('<L', 5) + b'hello', limits=None)
            self.assertEqual(len(call['Data']), 5)
        finally:
            setDefaultLimits(None)


class ConformantArrayLimitTests(unittest.TestCase):

    def test_exaggerated_count_fails_before_allocation(self):
        evil = pack('<L', 2_000_000_000) + b'abc'
        limits = NDRLimits(max_array_elements=1000)
        with self.assertRaises(NDRLimitError) as ctx:
            ConformantArrayCall(evil, limits=limits)
        self.assertEqual(ctx.exception.budget, 'max_array_elements')
        self.assertIn('ConformantArrayCall', '/'.join(ctx.exception.path))

    def test_legitimate_empty_conformant_array_decodes(self):
        call = ConformantArrayCall(pack('<L', 0), limits=NDRLimits())
        self.assertEqual(call['Data'], [])
        self.assertEqual(call.limits.array_elements, 0)

    def test_valid_conformant_array_decodes_ndr32_and_ndr64(self):
        for is_ndr64, width in ((False, '<L'), (True, '<Q')):
            wire = pack(width, 3) + b'abc'
            call = ConformantArrayCall(wire, isNDR64=is_ndr64, limits=NDRLimits())
            self.assertEqual(len(call['Data']), 3)
            self.assertEqual(call.limits.array_elements, 3)
            # Alignment/encoding must be identical with and without limits.
            legacy = ConformantArrayCall(wire, isNDR64=is_ndr64)
            self.assertEqual(call.getData(), legacy.getData())

    def test_primitive_item_array_charges_element_and_octet_budgets(self):
        wire = pack('<L', 3) + pack('<LLL', 1, 2, 3)
        call = LongArrayCall(wire, limits=NDRLimits())
        self.assertEqual(call.limits.array_elements, 3)
        self.assertEqual(call.limits.octets, 12)

    def test_octet_budget_trips_for_primitive_items(self):
        wire = pack('<L', 100000)
        with self.assertRaises(NDRLimitError) as ctx:
            LongArrayCall(wire, limits=NDRLimits(
                max_array_elements=10_000_000, max_octets=1000))
        self.assertEqual(ctx.exception.budget, 'max_octets')

    def test_truncated_conformant_array_raises_instead_of_filling_defaults(self):
        truncated = pack('<L', 5) + b'ab'
        with self.assertRaises(NDRLimitError) as ctx:
            ConformantArrayCall(truncated, limits=NDRLimits())
        self.assertEqual(ctx.exception.budget, 'max_octets')
        self.assertIn('truncated', ctx.exception.message)

    def test_truncated_count_header_is_reported(self):
        # Only two bytes where a four-byte MaximumCount is expected.
        with self.assertRaises(NDRLimitError) as ctx:
            ConformantArrayCall(b'\x05\x00', limits=NDRLimits())
        self.assertEqual(ctx.exception.budget, 'max_octets')


class VaryingArrayLimitTests(unittest.TestCase):

    def test_valid_varying_array(self):
        wire = pack('<LL', 0, 3) + b'xyz'
        call = VaryingArrayCall(wire, limits=NDRLimits())
        self.assertEqual(b''.join(call['Data']), b'xyz')
        self.assertEqual(call.limits.array_elements, 3)

    def test_offset_plus_actual_count_within_maximum_count(self):
        # MaximumCount=5, Offset=1, ActualCount=3 -> 1+3 <= 5, legal.
        wire = pack('<LLL', 5, 1, 3) + b'pqr'
        call = ConformantVaryingArrayCall(wire, limits=NDRLimits())
        self.assertEqual(b''.join(call['Data']), b'pqr')

    def test_offset_plus_actual_count_exceeds_maximum_count(self):
        wire = pack('<LLL', 4, 2, 5)  # 2 + 5 > 4
        with self.assertRaises(NDRLimitError) as ctx:
            ConformantVaryingArrayCall(wire, limits=NDRLimits())
        self.assertEqual(ctx.exception.budget, 'max_array_elements')
        self.assertIn('MaximumCount', ctx.exception.message)

    def test_truncated_varying_array_raises(self):
        wire = pack('<LL', 0, 4) + b'ab'
        with self.assertRaises(NDRLimitError) as ctx:
            VaryingArrayCall(wire, limits=NDRLimits())
        self.assertEqual(ctx.exception.budget, 'max_octets')

    def test_ndr64_conformant_varying_truncation_raises(self):
        wire = pack('<QQQ', 5, 0, 5) + b'ab'
        with self.assertRaises(NDRLimitError) as ctx:
            ConformantVaryingArrayCall(wire, isNDR64=True, limits=NDRLimits())
        self.assertEqual(ctx.exception.budget, 'max_octets')

    def test_ndr64_alignment_unchanged_under_limits(self):
        for is_ndr64, width in ((False, '<L'), (True, '<Q')):
            wire = pack(width, 4) + pack(width, 0) + pack(width, 2) + b'ab'
            limited = ConformantVaryingArrayCall(
                wire, isNDR64=is_ndr64, limits=NDRLimits())
            legacy = ConformantVaryingArrayCall(wire, isNDR64=is_ndr64)
            self.assertEqual(limited.getData(), legacy.getData())


class PointerAndReferentTests(unittest.TestCase):

    def test_null_pointer_is_not_charged(self):
        for is_ndr64, blob in ((False, b'\x00' * 4), (True, b'\x00' * 8)):
            call = NullPointerCall(blob, isNDR64=is_ndr64, limits=NDRLimits())
            # NDRPOINTERNULL stores the zero indicator in its Data field.
            self.assertEqual(call.fields['Ptr']['Data'], 0)
            self.assertEqual(call.limits.referents, 0)

    def test_non_null_pointer_charges_one_referent(self):
        wire = pack('<L', 0x1234) + pack('<L', 7)
        call = PointerCall(wire, limits=NDRLimits())
        self.assertEqual(call.limits.referents, 1)

    def test_ndr64_non_null_pointer_roundtrip(self):
        wire = pack('<Q', 0x999) + pack('<L', 7)
        limited = PointerCall(wire, isNDR64=True, limits=NDRLimits())
        legacy = PointerCall(wire, isNDR64=True)
        self.assertEqual(limited.getData(), legacy.getData())
        self.assertEqual(limited.limits.referents, 1)

    def test_truncated_pointer_indicator_raises(self):
        with self.assertRaises(NDRLimitError) as ctx:
            PointerCall(b'\x01\x02', limits=NDRLimits())
        self.assertEqual(ctx.exception.budget, 'max_octets')

    def test_shared_referent_id_is_observed_but_each_occurrence_charged(self):
        # Top-level holder pointer, two embedded pointers aliasing one id, and
        # one deferred body per pointer (the historical decode materializes both).
        wire = (pack('<L', 1)
                + pack('<LL', 0x4242, 0x4242)
                + pack('<LL', 55, 66))
        call = SharedPointerCall(wire, limits=NDRLimits())
        self.assertEqual(call.limits.referents, 3)
        self.assertIn(0x4242, call.limits.seen_referent_ids)

    def test_referent_budget_is_exhausted_before_deep_decode(self):
        wire = (pack('<L', 1)
                + pack('<LL', 0x4242, 0x4243)
                + pack('<LL', 55, 66))
        with self.assertRaises(NDRLimitError) as ctx:
            SharedPointerCall(wire, limits=NDRLimits(max_referents=1))
        self.assertEqual(ctx.exception.budget, 'max_referents')

    def test_optional_null_pointer_inside_structure_still_readable(self):
        # First pointer non-null, second optional pointer NULL.
        wire = pack('<LL', 0x1111, 0) + pack('<L', 9)
        call = NDRCALL()
        # Build inline through the Holder type for an explicit, readable layout.
        holder_call = SharedPointerCall(
            pack('<L', 1) + pack('<LL', 0x1111, 0) + pack('<L', 9),
            limits=NDRLimits())
        holder = holder_call.fields['Holder'].fields['Data']
        self.assertEqual(holder.fields['Second']['ReferentID'], 0)
        self.assertEqual(holder_call.limits.referents, 2)


class SharedBudgetAndDepthTests(unittest.TestCase):

    def test_element_budget_is_shared_across_nested_pointer_and_array(self):
        # Pointer referent id followed by an array claiming 5000 elements with
        # no backing element data.
        wire = pack('<L', 1) + pack('<L', 5000)
        with self.assertRaises(NDRLimitError) as ctx:
            NestedArrayCall(wire, limits=NDRLimits(max_array_elements=100))
        self.assertEqual(ctx.exception.budget, 'max_array_elements')
        # The error location names the nested structure chain.
        self.assertIn('NestedArrayCall', ctx.exception.path)

    def test_budgets_accumulate_across_multiple_arrays(self):
        class TwoArrayCall(NDRCALL):
            structure = (
                ('A', LongArray),
                ('B', LongArray),
            )

        wire = (pack('<L', 3) + pack('<LLL', 1, 2, 3)
                + pack('<L', 2) + pack('<LL', 4, 5))
        call = TwoArrayCall(wire, limits=NDRLimits())
        self.assertEqual(call.limits.array_elements, 5)
        self.assertEqual(call.limits.octets, 20)

    def test_depth_budget_is_enforced_and_balanced(self):
        limits = NDRLimits(max_depth=1)
        with self.assertRaises(NDRLimitError) as ctx:
            PrimitiveCall(pack('<LL', 1, 2), limits=limits)
        self.assertEqual(ctx.exception.budget, 'max_depth')

    def test_depth_returns_to_zero_after_nested_decode(self):
        wire = (pack('<L', 1)
                + pack('<LL', 10, 20)
                + pack('<L', 99)
                + pack('<LL', 1, 2))
        call = SharedPointerCall(wire, limits=NDRLimits())
        self.assertEqual(call.limits.depth, 0)
        self.assertGreater(call.limits.peak_depth, 1)

    def test_primitive_octet_budget(self):
        with self.assertRaises(NDRLimitError) as ctx:
            PrimitiveCall(pack('<LL', 1, 2), limits=NDRLimits(max_octets=4))
        self.assertEqual(ctx.exception.budget, 'max_octets')

    def test_error_names_structure_and_budget(self):
        try:
            ConformantArrayCall(pack('<L', 100),
                                limits=NDRLimits(max_array_elements=5))
        except NDRLimitError as err:
            self.assertEqual(err.budget, 'max_array_elements')
            self.assertEqual(err.structure, 'ByteArray')
            self.assertIn('ByteArray', err.message)
            self.assertIn('max_array_elements', err.message)
        else:
            self.fail('NDRLimitError was not raised')


class GlobalDefaultLimitTests(unittest.TestCase):

    def tearDown(self):
        setDefaultLimits(None)

    def test_process_wide_default_applies_without_explicit_limits(self):
        setDefaultLimits(NDRLimits(max_array_elements=10))
        with self.assertRaises(NDRLimitError):
            ConformantArrayCall(pack('<L', 50) + b'x')

    def test_clearing_default_restores_legacy_behavior(self):
        setDefaultLimits(NDRLimits(max_array_elements=1))
        setDefaultLimits(None)
        call = ConformantArrayCall(pack('<L', 0xFFFFFFFF) + b'x')
        self.assertIsNone(call.limits)


if __name__ == '__main__':
    unittest.main(verbosity=1)
