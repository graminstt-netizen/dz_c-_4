#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include <cstddef>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <system_error>


class File
{
public:

    // Открытие файла с выбрасыванием исключения при ошибке
    static File open(
        const std::filesystem::path& p,
        DWORD access,
        DWORD creation,
        bool append = false
    );


    // Открытие файла без выбрасывания исключений
    static std::expected<File, std::error_code> try_open(
        const std::filesystem::path& p,
        DWORD access,
        DWORD creation,
        bool append = false
    ) noexcept;


    // Запрещаем копирование
    File(const File&) = delete;

    File& operator=(const File&) = delete;


    // Разрешаем перемещение
    File(File&& other) noexcept;

    File& operator=(File&& other) noexcept;


    // Деструктор
    ~File();


    // Обмен содержимым
    void swap(File& other) noexcept;

    // Проверка открытия файла
    bool is_open() const noexcept;


    // Чтение данных
    std::size_t read(std::span<std::byte> buf);

    // Запись всех переданных данных
    void write_all(std::span<const std::byte> data);

    // Чтение всего файла без изменения позиции
    std::string read_all() const;


    // Повторное открытие файла
    void reopen(
        const std::filesystem::path& p,
        DWORD access,
        DWORD creation,
        bool append = false
    );


    // Явное закрытие
    void close();


private:

    // Создавать объекты можно только из методов класса
    File(HANDLE handle, bool append) noexcept
        : h_(handle), append_(append)
    {
    }

    // Дескриптор винды
    HANDLE h_ = INVALID_HANDLE_VALUE;

    // Признак режима дозаписи
    bool append_ = false;
};
