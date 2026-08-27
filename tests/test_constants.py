from bkcrypto import constants


class TestSymmetricMode:
    @classmethod
    def test_members__returns_all_modes_as_frozenset(cls) -> None:
        members = constants.SymmetricMode.members()

        assert members == frozenset(constants.SymmetricMode)

    @classmethod
    def test_block_size_iv_modes__returns_expected_modes(cls) -> None:
        modes = constants.SymmetricMode.block_size_iv_modes()

        assert modes == frozenset(
            {
                constants.SymmetricMode.CBC,
                constants.SymmetricMode.CFB,
                constants.SymmetricMode.CTR,
            }
        )
