defmodule ZtlpNs.NameValidatorTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.NameValidator

  # ──────────────────────────────────────────────────────────────────
  # Existing behaviour we want to preserve (regression guards)
  # ──────────────────────────────────────────────────────────────────

  describe "validate/1 — already-canonical lowercase names (regression)" do
    test "single-level lowercase name is valid" do
      assert :ok = NameValidator.validate("acme.ztlp")
    end

    test "multi-level lowercase name is valid (sub-zone)" do
      assert :ok = NameValidator.validate("tech-rockstars.trs.ztlp")
    end

    test "deep multi-level lowercase name is valid" do
      assert :ok = NameValidator.validate("deep.sub.zone.ztlp")
    end

    test "labels with hyphens in the middle are valid" do
      assert :ok = NameValidator.validate("tech-rockstars.trs.ztlp")
    end

    test "labels with digits at start are valid" do
      assert :ok = NameValidator.validate("1trsdc.trs.ztlp")
    end

    test "@ character is allowed (identity names)" do
      assert :ok = NameValidator.validate("steve@trs.ztlp")
    end

    test "empty name is rejected" do
      assert {:error, :empty_name} = NameValidator.validate("")
    end

    test "name with null byte is rejected" do
      assert {:error, :invalid_characters} = NameValidator.validate("foo" <> <<0>> <> ".ztlp")
    end

    test "underscore is still rejected (non-DNS character)" do
      # DNS labels do not permit underscores. This is intentional.
      assert {:error, :invalid_characters} = NameValidator.validate("foo_bar.ztlp")
    end

    test "trailing hyphen on label is rejected" do
      assert {:error, :invalid_characters} = NameValidator.validate("foo-.ztlp")
    end

    test "leading hyphen on label is rejected" do
      assert {:error, :invalid_characters} = NameValidator.validate("-foo.ztlp")
    end

    test "empty label between dots is rejected" do
      assert {:error, :empty_label} = NameValidator.validate("foo..ztlp")
    end

    test "name over 253 bytes is rejected" do
      long = String.duplicate("a", 254)
      assert {:error, :name_too_long} = NameValidator.validate(long)
    end
  end

  # ──────────────────────────────────────────────────────────────────
  # NEW behaviour: case-insensitive validation (DNS-aligned semantics)
  # ──────────────────────────────────────────────────────────────────

  describe "validate/1 — case-insensitive (NEW)" do
    test "uppercase host label is accepted" do
      # The exact case that broke TRSDC enrollment on 2026-05-29.
      assert :ok = NameValidator.validate("TRSDC.tech-rockstars.trs.ztlp")
    end

    test "all-uppercase name is accepted" do
      assert :ok = NameValidator.validate("ACME.ZTLP")
    end

    test "mixed-case labels at any depth are accepted" do
      assert :ok = NameValidator.validate("Mixed.Case.Zone.Ztlp")
    end

    test "uppercase with hyphens is accepted" do
      assert :ok = NameValidator.validate("TECH-ROCKSTARS.TRS.ZTLP")
    end

    test "uppercase with @ identity character is accepted" do
      assert :ok = NameValidator.validate("Steve@TRS.ZTLP")
    end
  end

  # ──────────────────────────────────────────────────────────────────
  # NEW: canonicalize/1 — return the lowercased form for storage / lookup
  # ──────────────────────────────────────────────────────────────────

  describe "canonicalize/1 (NEW)" do
    test "lowercases a mixed-case name" do
      assert "trsdc.tech-rockstars.trs.ztlp" =
               NameValidator.canonicalize("TRSDC.tech-rockstars.trs.ztlp")
    end

    test "already-lowercase name is unchanged" do
      assert "acme.ztlp" = NameValidator.canonicalize("acme.ztlp")
    end

    test "preserves hyphens, dots, and @" do
      assert "steve@trs.ztlp" = NameValidator.canonicalize("Steve@TRS.ZTLP")
    end
  end

  # ──────────────────────────────────────────────────────────────────
  # validate_with_suffix/2 also needs to be case-insensitive
  # ──────────────────────────────────────────────────────────────────

  describe "validate_with_suffix/2 — case-insensitive (NEW)" do
    test "uppercase host with matching lowercase suffix is accepted" do
      assert :ok = NameValidator.validate_with_suffix("TRSDC.trs.ztlp", "trs.ztlp")
    end

    test "lowercase host with uppercase suffix is accepted" do
      assert :ok = NameValidator.validate_with_suffix("trsdc.trs.ztlp", "TRS.ZTLP")
    end

    test "name not under suffix is rejected" do
      assert {:error, :invalid_zone_suffix} =
               NameValidator.validate_with_suffix("trsdc.other.ztlp", "trs.ztlp")
    end

    test "nil suffix skips check (regression)" do
      assert :ok = NameValidator.validate_with_suffix("TRSDC.trs.ztlp", nil)
    end
  end
end
