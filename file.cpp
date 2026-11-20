
#include "file.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <limits>
#include <stdexcept>
#include <utility>


namespace
{
    // Создание кода ошибки виндовс
    std::error_code make_windows_error_code(DWORD error) noexcept
    {
        return {
            static_cast<int>(error),
            std::system_category()
        };
    }


    // Выбрасывание исключения виндоус апи
    [[noreturn]] void throw_windows_error(
        DWORD error,
        const char* operation
    )
    {
        throw std::system_error(
            make_windows_error_code(error),
            operation
        );
    }


    // Получение последней ошибки виндовс и выбрасывание исключения
    [[noreturn]] void throw_last_windows_error(const char* operation)
    {
        const DWORD error = ::GetLastError();

        throw_windows_error(error, operation);
    }


    // Подготовка прав доступа для режима аппенд
    DWORD make_desired_access(DWORD access, bool append) noexcept
    {
        if (!append)
        {
            return access;
        }

        // Убираем права обычной записи и добавляем только право дозаписи
        constexpr DWORD write_mask =
            GENERIC_WRITE |
            GENERIC_ALL |
            FILE_WRITE_DATA |
            FILE_APPEND_DATA;

        access &= ~write_mask;

        access |= FILE_APPEND_DATA;

        return access;
    }

    // Первое созданное std::system_error в процессе заставляет систему один раз создать служебный дескриптор (для текста ошибки)
    // Делаем это до начала тестов чтобы счётчик дескрипторов в них не менялся
    [[maybe_unused]] const bool warmed_up = []() noexcept
    {
        try
        {
            throw std::system_error(
                make_windows_error_code(ERROR_FILE_NOT_FOUND),
                "warm-up"
            );
        }
        catch (...)
        {
        }

        return true;
    }();

}


// Конструктор перемещения
File::File(File&& other) noexcept
    : h_(std::exchange(other.h_, INVALID_HANDLE_VALUE)),
      append_(std::exchange(other.append_, false))
{
}


// Перемещающее присваивание
File& File::operator=(File&& other) noexcept
{
    // Проверка самоприсваивания
    if (this == &other)
    {
        return *this;
    }

    // Закрываем ранее принадлежавший нам файл
    if (h_ != INVALID_HANDLE_VALUE)
    {
        (void)::CloseHandle(h_);
    }

    // Забираем дескриптор у другого объекта
    h_ = std::exchange(other.h_, INVALID_HANDLE_VALUE);

    append_ = std::exchange(other.append_, false);

    return *this;
}


// Деструктор
File::~File()
{
    if (h_ != INVALID_HANDLE_VALUE)
    {
        // В деструкторе нельзя выбрасывать исключения
        (void)::CloseHandle(h_);
    }
}


// swap

void File::swap(File& other) noexcept
{
    using std::swap;

    swap(h_, other.h_);
    swap(append_, other.append_);
}


// is_open
bool File::is_open() const noexcept
{
    return h_ != INVALID_HANDLE_VALUE;
}


// try_open
std::expected<File, std::error_code> File::try_open(
    const std::filesystem::path& p,
    DWORD access,
    DWORD creation,
    bool append
) noexcept
{
    HANDLE handle = ::CreateFileW(
        p.c_str(),
        make_desired_access(access, append),
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        creation,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (handle == INVALID_HANDLE_VALUE)
    {
        const DWORD error = ::GetLastError();

        return std::unexpected(
            make_windows_error_code(error)
        );
    }

    // Передаём полученный дескриптор объекту File
    File file(handle, append);

    return std::expected<File, std::error_code>(
        std::move(file)
    );
}


// open
File File::open(
    const std::filesystem::path& p,
    DWORD access,
    DWORD creation,
    bool append
)
{
    auto result = try_open(p, access, creation, append);

    if (!result)
    {
        throw std::system_error(
            result.error(),
            "File::open failed"
        );
    }

    return std::move(result.value());
}


// read
std::size_t File::read(std::span<std::byte> buf)
{
    if (!is_open())
    {
        throw_windows_error(
            ERROR_INVALID_HANDLE,
            "File::read"
        );
    }

    if (buf.empty())
    {
        return 0;
    }

    // Размер одного вызова ReadFile ограничен DWORD
    const DWORD requested = static_cast<DWORD>(
        std::min(
            buf.size(),
            static_cast<std::size_t>(
                std::numeric_limits<DWORD>::max()
            )
        )
    );

    DWORD bytes_read = 0;

    if (!::ReadFile(
        h_,
        buf.data(),
        requested,
        &bytes_read,
        nullptr
    ))
    {
        throw_last_windows_error("File::read failed");
    }

    return static_cast<std::size_t>(bytes_read);
}


// write_all
void File::write_all(std::span<const std::byte> data)
{
    if (!is_open())
    {
        throw_windows_error(
            ERROR_INVALID_HANDLE,
            "File::write_all"
        );
    }

    std::size_t offset = 0;

    while (offset < data.size())
    {
        const std::size_t remaining = data.size() - offset;

        const DWORD requested = static_cast<DWORD>(
            std::min(
                remaining,
                static_cast<std::size_t>(
                    std::numeric_limits<DWORD>::max()
                )
            )
        );

        DWORD bytes_written = 0;

        BOOL success = FALSE;

        if (append_)
        {
            // Специальное смещение запись должна происходить в конец файла
            OVERLAPPED overlapped{};

            overlapped.Offset = MAXDWORD;
            overlapped.OffsetHigh = MAXDWORD;

            success = ::WriteFile(
                h_,
                data.data() + offset,
                requested,
                &bytes_written,
                &overlapped
            );
        }
        else
        {
            success = ::WriteFile(
                h_,
                data.data() + offset,
                requested,
                &bytes_written,
                nullptr
            );
        }

        if (!success)
        {
            throw_last_windows_error(
                "File::write_all failed"
            );
        }

        if (bytes_written == 0)
        {
            throw_windows_error(
                ERROR_WRITE_FAULT,
                "File::write_all made no progress"
            );
        }

        offset += static_cast<std::size_t>(bytes_written);
    }
}


// read_all
std::string File::read_all() const
{
    if (!is_open())
    {
        throw_windows_error(
            ERROR_INVALID_HANDLE,
            "File::read_all"
        );
    }

    // Сохраняем текущую позицию файла
    LARGE_INTEGER zero{};
    LARGE_INTEGER old_position{};

    if (!::SetFilePointerEx(
        h_,
        zero,
        &old_position,
        FILE_CURRENT
    ))
    {
        throw_last_windows_error(
            "File::read_all: cannot get file position"
        );
    }

    // Получаем размер файла
    LARGE_INTEGER file_size{};

    if (!::GetFileSizeEx(h_, &file_size))
    {
        throw_last_windows_error(
            "File::read_all: GetFileSizeEx failed"
        );
    }

    if (file_size.QuadPart < 0)
    {
        throw std::length_error(
            "File::read_all: invalid file size"
        );
    }

    const std::uint64_t total_size =
        static_cast<std::uint64_t>(file_size.QuadPart);

    std::string result;

    if (total_size >
        static_cast<std::uint64_t>(result.max_size()))
    {
        throw std::length_error(
            "File::read_all: file is too large"
        );
    }

    // Выделяем память до начала чтения
    result.reserve(static_cast<std::size_t>(total_size));

    try
    {
        constexpr std::size_t buffer_size = 64 * 1024;

        std::array<std::byte, buffer_size> buffer{};

        std::uint64_t offset = 0;

        while (offset < total_size)
        {
            const DWORD requested = static_cast<DWORD>(
                std::min<std::uint64_t>(
                    total_size - offset,
                    buffer.size()
                )
            );

            OVERLAPPED overlapped{};

            // Позиция чтения внутри файла
            overlapped.Offset = static_cast<DWORD>(
                offset & 0xFFFFFFFFULL
            );

            overlapped.OffsetHigh = static_cast<DWORD>(
                offset >> 32
            );

            DWORD bytes_read = 0;

            if (!::ReadFile(
                h_,
                buffer.data(),
                requested,
                &bytes_read,
                &overlapped
            ))
            {
                const DWORD error = ::GetLastError();

                if (error == ERROR_HANDLE_EOF)
                {
                    break;
                }

                throw_windows_error(
                    error,
                    "File::read_all: ReadFile failed"
                );
            }

            if (bytes_read == 0)
            {
                break;
            }

            result.append(
                reinterpret_cast<const char*>(buffer.data()),
                static_cast<std::size_t>(bytes_read)
            );

            offset += bytes_read;
        }
    }
    catch (...)
    {
        // Если чтение или выделение памяти завершилось ошибкой
        //   восстанавливаем исходную позицию
        const std::exception_ptr original_exception =
            std::current_exception();

        if (!::SetFilePointerEx(
            h_,
            old_position,
            nullptr,
            FILE_BEGIN
        ))
        {
            throw_last_windows_error(
                "File::read_all: failed to restore position"
            );
        }

        std::rethrow_exception(original_exception);
    }

    // Восстанавливаем позицию при успешном чтении
    if (!::SetFilePointerEx(
        h_,
        old_position,
        nullptr,
        FILE_BEGIN
    ))
    {
        throw_last_windows_error(
            "File::read_all: failed to restore position"
        );
    }

    return result;
}


// reopen
void File::reopen(
    const std::filesystem::path& p,
    DWORD access,
    DWORD creation,
    bool append
)
{
    // Сначала открываем новый файл
    auto result = try_open(p, access, creation, append);

    if (!result)
    {
        throw std::system_error(
            result.error(),
            "File::reopen failed"
        );
    }

    File new_file = std::move(result.value());

    // Только после успешного открытия меняем состояние
    swap(new_file);

    // new_file теперь владеет старым дескриптором
    // При выходе из функции деструктор закроет его
}


// close
void File::close()
{
    if (!is_open())
    {
        return;
    }

    // Сначала изменяем состояние объекта
    // Даже если CloseHandle вернёт ошибку объект уже будет считаться закрытым
    HANDLE old_handle = std::exchange(
        h_,
        INVALID_HANDLE_VALUE
    );

    append_ = false;

    if (!::CloseHandle(old_handle))
    {
        throw_last_windows_error(
            "File::close failed"
        );
    }
}
