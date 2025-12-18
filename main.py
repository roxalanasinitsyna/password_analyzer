"""Модуль для входа в программу анализа сложности паролей.
Он импортирует основные функции из модуля password_analyzer и
предоставляет основную функцию main() для запуска приложения.
"""

from password_analyzer import (
    analyze_password_complexity,
    display_analysis_results,
    execute_password_analysis_workflow,
    generate_improvement_variants,
    display_improvement_suggestions,
    generate_secure_password,
    is_positive_response
)


def main():
    """Основная функция программы.

    :returns: Код завершения программы
    :rtype: int
    :raises KeyboardInterrupt: При прерывании программы пользователем
    """
    try:
        exit_code = execute_password_analysis_workflow()
        return exit_code
    except KeyboardInterrupt:
        print("\n\nПрограмма прервана пользователем.")
        return 0
    except Exception as e:
        print(f"Критическая ошибка: {e}")
        return 1


if __name__ == "__main__":
    result = main()
    exit(result)