"""Приложение для анализа и улучшения сложности паролей.

Это приложение предоставляет функционал для:
1. Анализа сложности паролей (оценка, энтропия, проверка типов символов)
2. Генерации улучшенных вариантов паролей
3. Создания новых безопасных паролей

Основные возможности:
- Оценка пароля по шкале от 0 до 10
- Вычисление энтропии пароля в битах
- Проверка использования различных типов символов
- Генерация предложений по улучшению пароля
- Создание новых паролей на основе пользовательского ввода

Весь код написан с нуля, без заимствований из других проектов.
"""

import math
import random


def check_password_characters(password: str) -> tuple[bool, bool, bool, bool]:
    """Анализирует строку пароля на наличие различных типов символов.

    :param password: Анализируемая строка пароля
    :type password: str
    :returns: Кортеж флагов наличия типов символов
              (цифры, строчные, заглавные, специальные)
    :rtype: tuple[bool, bool, bool, bool]
    """
    has_digits = False
    has_lower = False
    has_upper = False
    has_special = False

    for char in password:
        if char.isdigit():
            has_digits = True
        elif char.islower():
            has_lower = True
        elif char.isupper():
            has_upper = True
        elif not char.isalnum():
            has_special = True

    return has_digits, has_lower, has_upper, has_special


def compute_alphabet_size(char_flags: tuple[bool, bool, bool, bool]) -> int:
    """Вычисляет размер алфавита на основе флагов используемых типов символов.

    :param char_flags: Флаги наличия типов символов
                       (цифры, строчные, заглавные, специальные)
    :type char_flags: tuple[bool, bool, bool, bool]
    :returns: Размер алфавита (сумма размеров использованных наборов символов)
    :rtype: int
    """
    size = 0
    contributions = [
        (char_flags[0], 10),
        (char_flags[1], 26),
        (char_flags[2], 26),
        (char_flags[3], 32),
    ]

    for flag, value in contributions:
        if flag:
            size += value

    return size


def compute_entropy_bits(password_length: int, alphabet_size: int) -> float:
    """Вычисляет энтропию пароля в битах по длине и размеру алфавита.

    :param password_length: Длина пароля
    :type password_length: int
    :param alphabet_size: Размер алфавита символов
    :type alphabet_size: int
    :returns: Значение энтропии в битах
    :rtype: float
    """
    if password_length <= 0 or alphabet_size <= 0:
        return 0.0

    total_combinations = alphabet_size**password_length
    if total_combinations <= 0:
        return 0.0

    return math.log2(total_combinations)


def map_entropy_to_score(entropy_value: float) -> float:
    """Преобразует значение энтропии в балл по шкале от 0 до 10.

    :param entropy_value: Значение энтропии пароля в битах
    :type entropy_value: float
    :returns: Балл сложности пароля от 0.0 до 10.0, округленный до десятых
    :rtype: float
    :raises ValueError: Если значение энтропии отрицательное
    """
    if entropy_value < 0:
        raise ValueError("Значение энтропии не может быть отрицательным")
    
    if entropy_value <= 0:
        return 0.0
    
    score = min(entropy_value / 10, 10.0)
    return round(score, 1)


def analyze_password_complexity(password: str) -> dict:
    """Проводит полный анализ сложности пароля.

    :param password: Анализируемый пароль
    :type password: str
    :returns: Словарь с результатами анализа
    :rtype: dict
    :raises ValueError: Если пароль пустой
    """
    if password is None or len(password) == 0:
        raise ValueError("Пароль не может быть пустым")

    char_flags = check_password_characters(password)
    alphabet_size = compute_alphabet_size(char_flags)
    entropy_value = compute_entropy_bits(len(password), alphabet_size)
    score_value = map_entropy_to_score(entropy_value)

    if score_value < 0:
        score_value = 0.0
    if score_value > 10:
        score_value = 10.0

    score_value = round(score_value, 1)

    return {
        "score": score_value,
        "entropy": round(entropy_value, 1),
        "has_digits": char_flags[0],
        "has_lower": char_flags[1],
        "has_upper": char_flags[2],
        "has_special": char_flags[3],
        "length": len(password),
        "alphabet_size": alphabet_size,
    }


def get_recommendation(score: float) -> str:
    """Возвращает текстовую рекомендацию на основе балла сложности пароля.

    :param score: Балл сложности пароля (0-10)
    :type score: float
    :returns: Текстовая рекомендация
    :rtype: str
    """
    if score < 4:
        return "МИНИМАЛЬНОЕ УЛУЧШЕНИЕ - всё ещё слабый пароль"
    elif score < 6:
        return "ХОРОШЕЕ УЛУЧШЕНИЕ - приемлемая безопасность"
    elif score < 8:
        return "ОТЛИЧНОЕ УЛУЧШЕНИЕ - хорошая безопасность"
    else:
        return "ПРЕВОСХОДНО - очень высокий уровень безопасности"


def is_positive_response(response: str) -> bool:
    """Проверяет, является ли ответ пользователя положительным.

    :param response: Ответ пользователя
    :type response: str
    :returns: True если ответ положительный, иначе False
    :rtype: bool
    """
    return response.strip().lower() in ["да", "д", "y", "yes", "1"]


def display_analysis_results(analysis_data: dict, original_password: str) -> None:
    """Отображает результаты анализа пароля в консоли.

    :param analysis_data: Результаты анализа пароля
    :type analysis_data: dict
    :param original_password: Оригинальный пароль
    :type original_password: str
    """
    print(f"\n{'='*60}")
    print(f"АНАЛИЗ ПАРОЛЯ: {original_password}")
    print(f"{'='*60}")
    print(f"Длина пароля: {analysis_data['length']} символов")
    print(f"Оценка сложности: {analysis_data['score']}/10")
    print(f"Энтропия (log2 вариантов): {analysis_data['entropy']} бит")
    print("\nИспользуемые типы символов:")

    char_types = [
        ("Цифры", "has_digits"),
        ("Строчные буквы", "has_lower"),
        ("Заглавные буквы", "has_upper"),
        ("Специальные символы", "has_special"),
    ]

    for name, key in char_types:
        symbol = "Присутствуют" if analysis_data[key] else "Отсутствуют"
        print(f"  ~ {name}: {symbol}")


def create_improvement_variant(
    original_password: str, 
    suffix: str, 
    description: str, 
    improvement_type: str
) -> dict:
    """Создает вариант улучшенного пароля с описанием.

    :param original_password: Оригинальный пароль
    :type original_password: str
    :param suffix: Суффикс для добавления к паролю
    :type suffix: str
    :param description: Описание улучшения
    :type description: str
    :param improvement_type: Тип улучшения (simple, moderate, good, etc.)
    :type improvement_type: str
    :returns: Словарь с информацией о варианте улучшения
    :rtype: dict
    """
    new_password = original_password + suffix
    score = analyze_password_complexity(new_password)["score"]

    return {
        "password": new_password,
        "score": score,
        "description": description,
        "improvement_type": improvement_type,
    }


def generate_improvement_variants(original_password: str) -> list[dict]:
    """Генерирует варианты улучшения оригинального пароля.

    :param original_password: Оригинальный пароль для улучшения
    :type original_password: str
    :returns: Список вариантов улучшения (до 5 вариантов)
    :rtype: list[dict]
    """
    variants = []
    original_analysis = analyze_password_complexity(original_password)

    def get_random_digit() -> str:
        """Генерирует случайную десятичную цифру.
    
        :returns: Случайная цифра от '0' до '9'
        :rtype: str
        """
        return random.choice("0123456789")

    def get_random_lower() -> str:
        """Генерирует случайную строчную букву английского алфавита.
    
        :returns: Случайная буква от 'a' до 'z'
        :rtype: str
        """
        return random.choice("abcdefghijklmnopqrstuvwxyz")

    def get_random_upper() -> str:
        """Генерирует случайную заглавную букву английского алфавита.
    
        :returns: Случайная буква от 'A' до 'Z'
        :rtype: str
        """
        return random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    def get_random_special() -> str:
        """Генерирует случайный специальный символ из набора.
    
        :returns: Случайный специальный символ
        :rtype: str
        """
        return random.choice('!@#$%^&*()_+-=[]{}|;:,.<>?\"/~`')

    improvement_specs = [
        (
            lambda: get_random_digit(),
            lambda s: f"Добавлена цифра {s} в конец",
            "simple",
            not original_analysis["has_digits"],
        ),
        (
            lambda: get_random_upper(),
            lambda s: f"Добавлена заглавная буква {s} в конец",
            "moderate",
            not original_analysis["has_upper"],
        ),
        (
            lambda: get_random_special(),
            lambda s: f"Добавлен специальный символ {s}",
            "good",
            not original_analysis["has_special"],
        ),
        (
            lambda: get_random_digit() + get_random_special(),
            lambda s: f"Добавлена случайная комбинация {s}",
            "better",
            True,
        ),
        (
            lambda: get_random_lower()
            + get_random_upper()
            + get_random_digit()
            + get_random_special(),
            lambda s: f"Добавлен случайный паттерн {s}",
            "excellent",
            True,
        ),
    ]

    for get_suffix, get_description, imp_type, condition in improvement_specs:
        if condition:
            suffix = get_suffix()
            description = get_description(suffix)
            variant = create_improvement_variant(
                original_password, suffix, description, imp_type
            )
            variants.append(variant)

    if original_password and any(c.islower() for c in original_password):
        lower_indices = [i for i, c in enumerate(original_password) if c.islower()]
        if lower_indices:
            random_index = random.choice(lower_indices)
            new_chars = list(original_password)
            new_chars[random_index] = new_chars[random_index].upper()
            variant2 = "".join(new_chars)
            score2 = analyze_password_complexity(variant2)["score"]
            variants.append(
                {
                    "password": variant2,
                    "score": score2,
                    "description": f"Случайная буква сделана заглавной (позиция {random_index+1})",
                    "improvement_type": "moderate",
                }
            )

    if len(original_password) < 20:
        random_suffix = get_random_digit() + get_random_special()
        variant3 = original_password + original_password[::-1] + random_suffix
        score3 = analyze_password_complexity(variant3)["score"]
        variants.append(
            {
                "password": variant3,
                "score": score3,
                "description": f"Пароль удвоен в обратном порядке с добавлением {random_suffix}",
                "improvement_type": "strong",
            }
        )

    if original_password:
        replacement_options = {
            "a": ["@", "4"],
            "e": ["3", "€"],
            "i": ["1", "!"],
            "o": ["0", "()"],
            "s": ["$", "5"],
            "t": ["7", "+"],
            "A": ["4", "@"],
            "E": ["3", "€"],
            "I": ["1", "!"],
            "O": ["0", "()"],
            "S": ["$", "5"],
            "T": ["7", "+"],
            "b": ["8", "|3"],
            "g": ["9", "&"],
            "l": ["1", "|"],
            "z": ["2", "%"],
        }

        modified = list(original_password)
        replacements_made = []

        for i, char in enumerate(modified):
            if char in replacement_options and random.random() < 0.3:
                possible_replacements = replacement_options[char]
                new_char = random.choice(possible_replacements)
                modified[i] = new_char
                replacements_made.append(f"'{char}' заменяется на '{new_char}'")

        if replacements_made:
            variant4 = "".join(modified)
            score4 = analyze_password_complexity(variant4)["score"]
            variants.append(
                {
                    "password": variant4,
                    "score": score4,
                    "description": f'Заменены символы: {", ".join(replacements_made[:3])}'
                    + (" и другие" if len(replacements_made) > 3 else ""),
                    "improvement_type": "creative",
                }
            )

    weak_points = []
    if not original_analysis["has_digits"]:
        weak_points.append("нет цифр")
    if not original_analysis["has_upper"]:
        weak_points.append("нет заглавных букв")
    if not original_analysis["has_special"]:
        weak_points.append("нет спецсимволов")
    if original_analysis["length"] < 8:
        weak_points.append(f'слишком короткий ({original_analysis["length"]} символов)')

    if weak_points:
        random_weak_point = random.choice(weak_points)
        if "нет цифр" in random_weak_point:
            variant5 = original_password + get_random_digit() + get_random_digit()
        elif "нет заглавных букв" in random_weak_point:
            if original_password and any(c.isalpha() for c in original_password):
                letter_indices = [
                    i for i, c in enumerate(original_password) if c.isalpha()
                ]
                random_index = random.choice(letter_indices)
                new_chars = list(original_password)
                new_chars[random_index] = new_chars[random_index].upper()
                variant5 = "".join(new_chars)
            else:
                variant5 = original_password + get_random_upper()
        elif "нет спецсимволов" in random_weak_point:
            variant5 = original_password + get_random_special()
        elif "слишком короткий" in random_weak_point:
            random_combo = (
                get_random_lower()
                + get_random_upper()
                + get_random_digit()
                + get_random_special()
            )
            variant5 = original_password + random_combo
        else:
            variant5 = (
                original_password
                + get_random_special()
                + get_random_upper()
                + get_random_digit()
            )

        score5 = analyze_password_complexity(variant5)["score"]
        variants.append(
            {
                "password": variant5,
                "score": score5,
                "description": f"Исправлено: {random_weak_point}",
                "improvement_type": "smart",
            }
        )

    if len(original_password) < 15:
        added_chars = "".join(
            [
                get_random_digit(),
                get_random_lower(),
                get_random_upper(),
                get_random_special(),
            ]
        )
        all_chars = list(original_password + added_chars)
        random.shuffle(all_chars)
        variant6 = "".join(all_chars)
        target_length = max(8, len(original_password) + 4)

        if len(variant6) > target_length:
            variant6 = variant6[:target_length]

        score6 = analyze_password_complexity(variant6)["score"]
        variants.append(
            {
                "password": variant6,
                "score": score6,
                "description": "Случайная перестановка с добавлением следующих символов",
                "improvement_type": "strong",
            }
        )

    original_score = original_analysis["score"]
    filtered_variants = [v for v in variants if v["score"] > original_score]
    filtered_variants.sort(key=lambda x: x["score"])

    complexity_levels = [
        "simple",
        "moderate",
        "good",
        "better",
        "excellent",
        "strong",
        "creative",
        "smart",
    ]
    final_variants = []

    for level in complexity_levels:
        level_variants = [
            v for v in filtered_variants if v["improvement_type"] == level
        ]
        if level_variants:
            random_variant = random.choice(level_variants)
            final_variants.append(random_variant)

    if len(final_variants) > 5:
        final_variants = random.sample(final_variants, 5)

    final_variants.sort(key=lambda x: x["score"])
    return final_variants[:5]


def display_improvement_suggestions(
    original_password: str, 
    variants: list[dict], 
    original_score: float
) -> None:
    """Отображает предложения по улучшению пароля.

    :param original_password: Оригинальный пароль
    :type original_password: str
    :param variants: Варианты улучшенных паролей
    :type variants: list[dict]
    :param original_score: Оценка оригинального пароля
    :type original_score: float
    """
    print(f"\n{'='*60}")
    print(f"ПРЕДЛОЖЕНИЯ ПО УЛУЧШЕНИЮ (оригинальный балл: {original_score}/10)")
    print(f"{'='*60}")

    if not variants:
        print("Нет доступных улучшений для этого пароля.")
        return

    print("\nВарианты отсортированы по возрастанию сложности:")
    print("-" * 60)

    for i, variant in enumerate(variants, 1):
        improvement = variant["score"] - original_score
        print(f"\nВАРИАНТ {i} (оценка: {variant['score']}/10, +{improvement:.1f}):")
        print(f"  Пароль: {variant['password']}")
        print(f"  Изменение: {variant['description']}")
        recommendation = get_recommendation(variant["score"])
        print(f"  Рекомендация: {recommendation}")

    print(f"\n{'='*60}")
    print("СОВЕТ: Выберите вариант, который балансирует между сложностью")
    print("       и удобством запоминания для вас.")


def generate_character_sets() -> dict[str, str]:
    """Возвращает наборы символов для генерации паролей.

    :returns: Словарь с наборами символов разных типов
    :rtype: dict[str, str]
    """
    return {
        "digits": "0123456789",
        "lower": "abcdefghijklmnopqrstuvwxyz",
        "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "special": "!@#$%^&*()_+-=[]{}|;:,.<>?\"'`~",
    }


def generate_secure_password(base_string: str, target_length: int = 14) -> str:
    """Генерирует безопасный пароль на основе базовой строки.

    :param base_string: Базовая строка для генерации пароля
    :type base_string: str
    :param target_length: Целевая длина пароля (по умолчанию 14)
    :type target_length: int
    :returns: Сгенерированный пароль
    :rtype: str
    :raises ValueError: Если базовая строка пустая
    """
    if base_string is None or len(base_string) == 0:
        raise ValueError("Базовая строка не может быть пустой")

    seed_value = hash(base_string) + target_length
    random.seed(seed_value)
    
    char_sets = generate_character_sets()
    all_chars = (
        char_sets["digits"]
        + char_sets["lower"]
        + char_sets["upper"]
        + char_sets["special"]
    )

    password_parts = []
    
    mandatory_chars = [
        random.choice(char_sets["digits"]),
        random.choice(char_sets["lower"]),
        random.choice(char_sets["upper"]),
        random.choice(char_sets["special"]),
    ]
    
    password_parts.extend(mandatory_chars)

    base_part_max_len = min(len(base_string), target_length - len(password_parts))
    if base_part_max_len > 0:
        start_idx = random.randint(0, max(0, len(base_string) - base_part_max_len))
        base_part = base_string[start_idx:start_idx + base_part_max_len]
        password_parts.append(base_part)

    current_length = sum(len(part) for part in password_parts)
    if current_length < target_length:
        remaining = target_length - current_length
        for _ in range(remaining):
            password_parts.append(random.choice(all_chars))
    
    all_chars_list = list("".join(password_parts))
    random.shuffle(all_chars_list)
    generated_password = "".join(all_chars_list)
    
    generated_password = generated_password[:target_length]
    
    while len(generated_password) < target_length:
        generated_password += random.choice(all_chars)
        generated_password = generated_password[:target_length]
    
    random.seed()
    
    return generated_password


def analyze_existing_password() -> None:
    """Анализирует существующий пароль пользователя.

    Функция запрашивает у пользователя пароль, проводит анализ его сложности,
    отображает результаты и предлагает варианты улучшения при необходимости.
    Пользователь может вернуться в главное меню, введя 'назад'.

    :raises ValueError: Если возникает ошибка при анализе пароля
    :raises Exception: При возникновении неожиданных ошибок
    """
    print("\n" + "-" * 60)
    
    while True:
        try:
            password = input("\nВведите пароль для анализа (или 'назад' для возврата): ").strip()
            
            if password.lower() == 'назад':
                return
            
            if not password:
                raise ValueError("Пароль не может быть пустым")
            
            analysis_result = analyze_password_complexity(password)
            display_analysis_results(analysis_result, password)
            
            min_score = 4.0
            auto_suggest = analysis_result["score"] < min_score
            
            if auto_suggest:
                print(f"\nВаш пароль слабый ({analysis_result['score']}/10). Рекомендуется улучшение.")
                improve_choice = input("Хотите увидеть варианты улучшения? (Да/Нет): ")
            else:
                improve_choice = input("\nХотите увидеть варианты улучшения пароля? (Да/Нет): ")
            
            if is_positive_response(improve_choice):
                improvement_variants = generate_improvement_variants(password)
                display_improvement_suggestions(
                    password, improvement_variants, analysis_result["score"]
                )
                
                if improvement_variants:
                    apply_choice = input("\nХотите применить один из вариантов улучшения? (Да/Нет): ")
                    if is_positive_response(apply_choice):
                        try:
                            variant_num = int(input(f"Введите номер варианта (1-{len(improvement_variants)}): "))
                            if 1 <= variant_num <= len(improvement_variants):
                                improved_password = improvement_variants[variant_num-1]["password"]
                                print(f"\nВыбран улучшенный пароль: {improved_password}")
                                improved_analysis = analyze_password_complexity(improved_password)
                                display_analysis_results(improved_analysis, improved_password)
                            else:
                                print("Неверный номер варианта.")
                        except ValueError:
                            print("Неверный формат номера.")
            
            break
            
        except ValueError as e:
            print(f"Ошибка: {e}")
        except Exception as e:
            print(f"Неожиданная ошибка: {e}")


def generate_new_password() -> None:
    """Генерирует новый пароль на основе пользовательского ввода.

    Функция запрашивает у пользователя базовую фразу и желаемую длину,
    затем генерирует безопасный пароль и отображает его с результатами анализа.
    Пользователь может вернуться в главное меню, введя 'назад'.

    :raises ValueError: Если введена некорректная длина пароля
    :raises Exception: При возникновении ошибок генерации пароля
    """
    print("\n" + "-" * 60)
    
    while True:
        try:
            base_input = input("\nВведите слово или фразу для генерации пароля (или 'назад' для возврата): ").strip()
            
            if base_input.lower() == 'назад':
                return
            
            if not base_input:
                raise ValueError("Нужно ввести основу для генерации")
            
            target_length = 14
            length_input = input("Желаемая длина пароля (по умолчанию 14): ").strip()
            
            if length_input:
                try:
                    target_length = int(length_input)
                except ValueError:
                    raise ValueError("Длина пароля должна быть числом")
                
                if target_length < 8:
                    print("Длина установлена в 8 символов (минимум).")
                    target_length = 8
                elif target_length > 50:
                    print("Длина ограничена 50 символами.")
                    target_length = 50
            
            generated_password = generate_secure_password(base_input, target_length)
            print(f"\nСгенерированный пароль: {generated_password}")
            generated_analysis = analyze_password_complexity(generated_password)
            display_analysis_results(generated_analysis, generated_password)
            
            use_choice = input("\nХотите получить улучшенную версию этого пароля? (Да/Нет): ")
            if is_positive_response(use_choice):
                try:
                    improved_password = generate_secure_password(generated_password, max(target_length + 4, 12))
                    print(f"\nСгенерированный улучшенный пароль: {improved_password}")
                    improved_analysis = analyze_password_complexity(improved_password)
                    display_analysis_results(improved_analysis, improved_password)
                except Exception as error:
                    print(f"Ошибка при генерации пароля: {error}")
            
            break
            
        except ValueError as e:
            print(f"Ошибка ввода: {e}")
        except Exception as error:
            print(f"Ошибка при генерации: {error}")


def execute_password_analysis_workflow() -> int:
    """Выполняет интерактивный рабочий процесс анализа пароля.

    :returns: Код завершения программы (0 - успех, 1 - ошибка)
    :rtype: int
    """
    print("=" * 60)
    print("Анализатор сложности паролей".center(60))
    print("=" * 60)
    
    while True:
        print("\nВыберите действие:")
        print("1. Проанализировать существующий пароль")
        print("2. Сгенерировать новый пароль")
        print("3. Выход")
        
        choice = input("\nВаш выбор (1-3): ").strip()
        
        if choice == "1":
            analyze_existing_password()
        elif choice == "2":
            generate_new_password()
        elif choice == "3":
            print("\nДо свидания!")
            break
        else:
            print("Неверный выбор. Попробуйте еще раз.")
    
    return 0


if __name__ == "__main__":
    execute_password_analysis_workflow()