import math
import pytest
from password_analyzer import (
    check_password_characters,
    compute_alphabet_size,
    compute_entropy_bits,
    map_entropy_to_score,
    analyze_password_complexity,
    generate_improvement_variants,
    generate_secure_password,
    get_recommendation,
    is_positive_response,
    display_analysis_results,
)


class TestCheckPasswordCharacters:
    
    def test_all_character_types(self):
        result = check_password_characters("Aa1!")
        assert result == (True, True, True, True)
    
    def test_only_digits(self):
        result = check_password_characters("123456")
        assert result == (True, False, False, False)
    
    def test_only_lowercase(self):
        result = check_password_characters("abcdef")
        assert result == (False, True, False, False)
    
    def test_only_uppercase(self):
        result = check_password_characters("ABCDEF")
        assert result == (False, False, True, False)
    
    def test_only_special(self):
        result = check_password_characters("!@#$%")
        assert result == (False, False, False, True)
    
    def test_empty_string(self):
        result = check_password_characters("")
        assert result == (False, False, False, False)
    
    def test_mixed_no_special(self):
        result = check_password_characters("Aa1")
        assert result == (True, True, True, False)


class TestComputeAlphabetSize:
    
    def test_all_types_true(self):
        char_flags = (True, True, True, True)
        assert compute_alphabet_size(char_flags) == 10 + 26 + 26 + 32  
    
    def test_only_digits_true(self):
        char_flags = (True, False, False, False)
        assert compute_alphabet_size(char_flags) == 10
    
    def test_digits_and_lowercase(self):
        char_flags = (True, True, False, False)
        assert compute_alphabet_size(char_flags) == 10 + 26  
    
    def test_only_special_true(self):
        char_flags = (False, False, False, True)
        assert compute_alphabet_size(char_flags) == 32
    
    def test_all_false(self):
        char_flags = (False, False, False, False)
        assert compute_alphabet_size(char_flags) == 0


class TestComputeEntropyBits:
    
    def test_normal_case(self):
        entropy = compute_entropy_bits(8, 26)
        expected = 8 * math.log2(26)
        assert abs(entropy - expected) < 0.0001
    
    def test_zero_length(self):
        assert compute_entropy_bits(0, 26) == 0.0
    
    def test_zero_alphabet(self):
        assert compute_entropy_bits(10, 0) == 0.0
    
    def test_negative_length(self):
        assert compute_entropy_bits(-5, 26) == 0.0
    
    def test_negative_alphabet(self):
        assert compute_entropy_bits(10, -10) == 0.0
    
    def test_single_character(self):
        entropy = compute_entropy_bits(1, 10)
        expected = math.log2(10)
        assert abs(entropy - expected) < 0.0001


class TestMapEntropyToScore:
    
    def test_zero_entropy(self):
        assert map_entropy_to_score(0) == 0.0
    
    def test_low_entropy(self):
        score = map_entropy_to_score(5)
        assert score == 0.5
        assert 0 <= score <= 1.0
    
    def test_mid_entropy(self):
        score = map_entropy_to_score(50)
        assert score == 5.0
        assert 4 <= score <= 6
    
    def test_high_entropy(self):
        score = map_entropy_to_score(80)
        assert score == 8.0
        assert 7 <= score <= 9
    
    def test_very_high_entropy(self):
        score = map_entropy_to_score(150)
        assert score == 10.0 
        assert score == 10.0
    
    def test_negative_entropy(self):
        with pytest.raises(ValueError, match="Значение энтропии не может быть отрицательным"):
            map_entropy_to_score(-10)
    
    def test_boundary_values(self):
        assert map_entropy_to_score(10) == 1.0
        assert map_entropy_to_score(20) == 2.0
        assert map_entropy_to_score(100) == 10.0
        assert map_entropy_to_score(101) == 10.0  
    
    def test_rounding(self):
        assert map_entropy_to_score(7) == 0.7
        assert map_entropy_to_score(7.77) == 0.8 
        assert map_entropy_to_score(99.9) == 10.0 


class TestAnalyzePasswordComplexity:
    
    def test_strong_password(self):
        result = analyze_password_complexity("StrongPass123!")
        assert "score" in result
        assert "entropy" in result
        assert result["has_digits"] == True
        assert result["has_lower"] == True
        assert result["has_upper"] == True
        assert result["has_special"] == True
        assert result["length"] == len("StrongPass123!")
        assert result["score"] >= 7.0
    
    def test_weak_password(self):
        result = analyze_password_complexity("123")
        assert result["score"] < 4.0
        assert result["length"] == len("123")
        assert result["has_upper"] == False
        assert result["has_special"] == False
    
    def test_empty_password(self):
        with pytest.raises(ValueError, match="Пароль не может быть пустым"):
            analyze_password_complexity("")
    
    def test_password_with_only_special_chars(self):
        result = analyze_password_complexity("!@#$%^")
        assert result["has_special"] == True
        assert result["has_digits"] == False
        assert result["has_lower"] == False
        assert result["has_upper"] == False
        assert result["score"] > 0


class TestGenerateImprovementVariants:
    
    def test_with_weak_password(self):
        variants = generate_improvement_variants("weak")
        assert isinstance(variants, list)
        assert len(variants) <= 5
        
        if variants:
            for variant in variants:
                assert "password" in variant
                assert "score" in variant
                assert "description" in variant
                assert "improvement_type" in variant
                assert len(variant["password"]) >= len("weak")
    
    def test_with_strong_password(self):
        variants = generate_improvement_variants("VeryStrongPass123!")
        assert isinstance(variants, list)
        assert len(variants) <= 5
        
    def test_with_empty_password_should_raise(self):
        with pytest.raises(ValueError, match="Пароль не может быть пустым"):
            generate_improvement_variants("")
    
    def test_variants_have_higher_score(self):
        original_password = "test123"
        variants = generate_improvement_variants(original_password)
        
        if variants:
            original_analysis = analyze_password_complexity(original_password)
            original_score = original_analysis["score"]
            
            for variant in variants:
                assert variant["score"] > original_score


class TestGenerateSecurePassword:
    
    def test_normal_generation(self):
        password = generate_secure_password("base", 14)
        assert len(password) == 14
        assert any(c.isdigit() for c in password)
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(not c.isalnum() for c in password)
        
    def test_different_lengths(self):
        for length in [8, 12, 16, 20]:
            password = generate_secure_password("test", length)
            assert len(password) == length
    
    def test_empty_base_string(self):
        with pytest.raises(ValueError, match="Базовая строка не может быть пустой"):
            generate_secure_password("", 10)
    
    def test_deterministic_generation(self):
        password1 = generate_secure_password("same_input", 12)
        password2 = generate_secure_password("same_input", 12)
        assert password1 == password2


class TestGetRecommendation:
    
    def test_minimal_score(self):
        assert "МИНИМАЛЬНОЕ" in get_recommendation(0)
        assert "МИНИМАЛЬНОЕ" in get_recommendation(3.9)
    
    def test_good_score(self):
        assert "ХОРОШЕЕ" in get_recommendation(4)
        assert "ХОРОШЕЕ" in get_recommendation(5.9)
    
    def test_excellent_score(self):
        assert "ОТЛИЧНОЕ" in get_recommendation(6)
        assert "ОТЛИЧНОЕ" in get_recommendation(7.9)
    
    def test_superb_score(self):
        assert "ПРЕВОСХОДНО" in get_recommendation(8)
        assert "ПРЕВОСХОДНО" in get_recommendation(10)


class TestIsPositiveResponse:
    
    def test_positive_responses(self):
        assert is_positive_response("да") == True
        assert is_positive_response("Да") == True
        assert is_positive_response("д") == True
        assert is_positive_response("y") == True
        assert is_positive_response("yes") == True
        assert is_positive_response("YES") == True
        assert is_positive_response("1") == True
    
    def test_negative_responses(self):
        assert is_positive_response("нет") == False
        assert is_positive_response("Нет") == False
        assert is_positive_response("н") == False
        assert is_positive_response("n") == False
        assert is_positive_response("no") == False
        assert is_positive_response("0") == False
        assert is_positive_response("") == False
        assert is_positive_response("   ") == False
    
    def test_with_whitespace(self):
        assert is_positive_response("  да  ") == True
        assert is_positive_response("  Да  ") == True
        assert is_positive_response(" y ") == True


class TestIntegration:
    
    def test_full_analysis_flow(self):
        password = "Test123!"
        
        analysis = analyze_password_complexity(password)
        assert analysis["length"] == len(password)
        
        char_flags = check_password_characters(password)
        alphabet_size = compute_alphabet_size(char_flags)
        
        entropy = compute_entropy_bits(len(password), alphabet_size)
        assert abs(analysis["entropy"] - entropy) < 0.1
        
        score = map_entropy_to_score(entropy)
        assert abs(analysis["score"] - score) < 0.1
        
        recommendation = get_recommendation(score)
        assert len(recommendation) > 0
    
    def test_improvement_flow(self):
        weak_password = "123"
        
        original_analysis = analyze_password_complexity(weak_password)
        
        variants = generate_improvement_variants(weak_password)
        
        if variants:
            variant = variants[0]
            improved_analysis = analyze_password_complexity(variant["password"])
            
            assert improved_analysis["score"] > original_analysis["score"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])