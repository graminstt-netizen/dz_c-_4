// Тесты к заданию «Безопасная обёртка над файлом ОС» (вариант Windows).
//
// Что проверяется:
//   * на этапе компиляции: интерфейс, noexcept, запрет копирования,
//     отсутствие способов получить или подсунуть HANDLE;
//   * во время работы: поведение каждого метода, запрет наследования
//     дескриптора, утечки дескрипторов, гарантии исключений.
//
// Ошибки, которые трудно получить честно (неполная запись, ошибка WriteFile
// посреди записи, ошибка CloseHandle), подстраиваются через подмену
// WriteFile и CloseHandle в таблице импорта (IAT) этого exe — см. namespace
// hook ниже. Подмена срабатывает только для одного HANDLE, выбранного тестом.
// Поэтому реализацию File нужно собирать в этот же exe или в статическую
// библиотеку, а не в DLL.
//
// После каждого теста TearDown сверяет число дескрипторов процесса
// (GetProcessHandleCount) с исходным, поэтому любая утечка роняет тест.
//
// Режим совместного доступа (dwShareMode) задание не задаёт, поэтому тесты
// читают файл со стороны только после того, как File закрыт, и подходят
// любые значения dwShareMode, включая 0.
//
// Сигнатура reopen в тестах: reopen(path, DWORD access, DWORD creation).
// Если у вас другие параметры, поправьте одну функцию do_reopen ниже.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "file.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

namespace fs = std::filesystem;

namespace {

constexpr DWORD kRead = GENERIC_READ;
constexpr DWORD kWrite = GENERIC_WRITE;
constexpr DWORD kReadWrite = GENERIC_READ | GENERIC_WRITE;

void do_reopen(File& f, const fs::path& p, DWORD access, DWORD creation = OPEN_EXISTING) {
    f.reopen(p, access, creation);
}

// ============================================================================
// Подмена WriteFile и CloseHandle через таблицу импорта
// ============================================================================

namespace hook {

std::atomic<HANDLE> target{INVALID_HANDLE_VALUE};  // перехватываем только этот HANDLE

std::atomic<int> close_calls{0};      // сколько раз вызвали CloseHandle(target)
std::atomic<DWORD> close_fail_error{0}; // != 0: закрыть по-настоящему, но вернуть ошибку

std::atomic<int> write_calls{0};             // сколько раз вызвали WriteFile(target)
std::atomic<DWORD> write_max_chunk{0};       // != 0: писать не больше стольких байт за вызов
std::atomic<int> write_fail_at{0};           // != 0: вызов с этим номером завершается ошибкой
std::atomic<DWORD> write_fail_error{0};

using WriteFile_t = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
using CloseHandle_t = BOOL(WINAPI*)(HANDLE);

WriteFile_t real_WriteFile = nullptr;
CloseHandle_t real_CloseHandle = nullptr;
bool write_hooked = false;
bool close_hooked = false;

void reset() {
    target = INVALID_HANDLE_VALUE;
    close_calls = 0;
    close_fail_error = 0;
    write_calls = 0;
    write_max_chunk = 0;
    write_fail_at = 0;
    write_fail_error = 0;
}

BOOL WINAPI fake_CloseHandle(HANDLE h) {
    if (h == INVALID_HANDLE_VALUE || h != target.load()) {
        return real_CloseHandle(h);
    }
    ++close_calls;
    const BOOL ok = real_CloseHandle(h);  // дескриптор освобождается в любом случае
    if (const DWORD e = close_fail_error.load(); e != 0) {
        SetLastError(e);
        return FALSE;
    }
    return ok;
}

BOOL WINAPI fake_WriteFile(HANDLE h, LPCVOID buf, DWORD n, LPDWORD written, LPOVERLAPPED ov) {
    if (h == INVALID_HANDLE_VALUE || h != target.load()) {
        return real_WriteFile(h, buf, n, written, ov);
    }
    const int call = ++write_calls;
    if (call == write_fail_at.load()) {
        if (written != nullptr) *written = 0;
        SetLastError(write_fail_error.load());
        return FALSE;
    }
    if (const DWORD max = write_max_chunk.load(); max > 0 && n > max) {
        n = max;
    }
    return real_WriteFile(h, buf, n, written, ov);
}

// Заменить в IAT главного модуля все импорты функции name на replacement.
bool patch_iat(const char* name, void* replacement) {
    auto* base = reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0) return false;

    bool patched = false;
    for (auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
         imp->Name != 0; ++imp) {
        if (imp->OriginalFirstThunk == 0) continue;
        auto* names = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->OriginalFirstThunk);
        auto* slots = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->FirstThunk);
        for (; names->u1.AddressOfData != 0; ++names, ++slots) {
            if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) continue;
            const auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + names->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(ibn->Name), name) != 0) continue;

            DWORD old = 0;
            VirtualProtect(&slots->u1.Function, sizeof(slots->u1.Function), PAGE_READWRITE, &old);
            slots->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
            VirtualProtect(&slots->u1.Function, sizeof(slots->u1.Function), old, &old);
            patched = true;
        }
    }
    return patched;
}

// Ставится до main, в том числе в дочерних процессах death-тестов.
[[maybe_unused]] const bool installed = [] {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    real_WriteFile = reinterpret_cast<WriteFile_t>(reinterpret_cast<void*>(GetProcAddress(k32, "WriteFile")));
    real_CloseHandle = reinterpret_cast<CloseHandle_t>(reinterpret_cast<void*>(GetProcAddress(k32, "CloseHandle")));
    write_hooked = patch_iat("WriteFile", reinterpret_cast<void*>(&fake_WriteFile));
    close_hooked = patch_iat("CloseHandle", reinterpret_cast<void*>(&fake_CloseHandle));
    return true;
}();

}  // namespace hook

#define REQUIRE_WRITE_HOOK()                                                         \
    if (!hook::write_hooked) {                                                       \
        GTEST_SKIP() << "не удалось подменить WriteFile в IAT (File собран в DLL?)"; \
    }
#define REQUIRE_CLOSE_HOOK()                                                           \
    if (!hook::close_hooked) {                                                         \
        GTEST_SKIP() << "не удалось подменить CloseHandle в IAT (File собран в DLL?)"; \
    }

// ============================================================================
// Проверки на этапе компиляции
// ============================================================================

using Path = const fs::path&;

static_assert(!std::is_copy_constructible_v<File>, "File не должен копироваться");
static_assert(!std::is_copy_assignable_v<File>, "File не должен копироваться");
static_assert(std::is_nothrow_move_constructible_v<File>, "перемещение должно быть noexcept");
static_assert(std::is_nothrow_move_assignable_v<File>, "перемещение должно быть noexcept");
static_assert(std::is_nothrow_destructible_v<File>, "деструктор должен быть noexcept");
static_assert(std::is_nothrow_swappable_v<File>, "std::swap(File&, File&) должен быть noexcept");

static_assert(noexcept(std::declval<File&>().swap(std::declval<File&>())), "swap должен быть noexcept");
static_assert(noexcept(std::declval<const File&>().is_open()), "is_open должен быть noexcept");
static_assert(noexcept(File::try_open(std::declval<Path>(), DWORD{}, DWORD{})), "try_open должен быть noexcept");

static_assert(std::is_same_v<decltype(File::open(std::declval<Path>(), DWORD{}, DWORD{})), File>);
static_assert(std::is_same_v<decltype(File::try_open(std::declval<Path>(), DWORD{}, DWORD{})),
                             std::expected<File, std::error_code>>);
static_assert(std::is_same_v<decltype(std::declval<File&>().read(std::declval<std::span<std::byte>>())),
                             std::size_t>);
static_assert(std::is_same_v<decltype(std::declval<const File&>().read_all()), std::string>,
              "read_all должен быть const и возвращать std::string");

// Создать File можно только через open/try_open.
static_assert(!std::is_default_constructible_v<File>, "File не должен создаваться по умолчанию");
static_assert(!std::is_constructible_v<File, HANDLE>, "нельзя создавать File из HANDLE");
static_assert(!std::is_convertible_v<HANDLE, File>, "нельзя создавать File из HANDLE");

// HANDLE не выходит наружу.
static_assert(!std::is_convertible_v<File, HANDLE>, "File не должен превращаться в HANDLE");
static_assert(!std::is_constructible_v<HANDLE, File&>, "File не должен превращаться в HANDLE");

template <class T> concept has_handle        = requires(T& t) { t.handle(); };
template <class T> concept has_get_handle    = requires(T& t) { t.get_handle(); };
template <class T> concept has_native_handle = requires(T& t) { t.native_handle(); };
template <class T> concept has_fd            = requires(T& t) { t.fd(); };
template <class T> concept has_get           = requires(T& t) { t.get(); };
template <class T> concept has_release       = requires(T& t) { t.release(); };
template <class T> concept has_public_h_     = requires(T& t) { t.h_; };

static_assert(!has_handle<File>, "геттер дескриптора запрещён");
static_assert(!has_get_handle<File>, "геттер дескриптора запрещён");
static_assert(!has_native_handle<File>, "геттер дескриптора запрещён");
static_assert(!has_fd<File>, "геттер дескриптора запрещён");
static_assert(!has_get<File>, "геттер дескриптора запрещён");
static_assert(!has_release<File>, "метод, отдающий дескриптор, запрещён");
static_assert(!has_public_h_<File>, "поле h_ должно быть приватным");

// ============================================================================
// Вспомогательные функции
// ============================================================================

std::span<const std::byte> bytes(std::string_view s) {
    return std::as_bytes(std::span(s.data(), s.size()));
}

std::string read_n(File& f, std::size_t n) {
    std::string out(n, '\0');
    const std::size_t got = f.read(std::as_writable_bytes(std::span(out)));
    EXPECT_LE(got, n) << "read вернул больше байт, чем размер буфера";
    out.resize(got);
    return out;
}

DWORD count_handles() {
    DWORD n = 0;
    GetProcessHandleCount(GetCurrentProcess(), &n);
    return n;
}

struct FileId {
    DWORD volume;
    DWORD high;
    DWORD low;
    bool operator==(const FileId&) const = default;
};

std::optional<FileId> id_of(HANDLE h) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h, &info)) return std::nullopt;
    return FileId{info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow};
}

// Идентификатор файла. Открываем только атрибуты, это не конфликтует
// с любым режимом совместного доступа.
std::optional<FileId> id_of(const fs::path& p) {
    HANDLE h = CreateFileW(p.c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::nullopt;
    auto id = id_of(h);
    CloseHandle(h);
    return id;
}

// HANDLE процесса, открытый на файл p (перебором значений дескрипторов).
std::optional<HANDLE> find_handle(const fs::path& p) {
    const auto target = id_of(p);
    if (!target) return std::nullopt;
    for (ULONG_PTR v = 4; v < 0x20000; v += 4) {
        HANDLE h = reinterpret_cast<HANDLE>(v);
        DWORD flags = 0;
        if (!GetHandleInformation(h, &flags)) continue;
        if (GetFileType(h) != FILE_TYPE_DISK) continue;
        if (id_of(h) == target) return h;
    }
    return std::nullopt;
}

bool is_inheritable(HANDLE h) {
    DWORD flags = 0;
    return GetHandleInformation(h, &flags) && (flags & HANDLE_FLAG_INHERIT) != 0;
}

std::error_code win_error(DWORD e) {
    return {static_cast<int>(e), std::system_category()};
}

template <class F>
void expect_system_error(F&& action, DWORD expected) {
    try {
        std::forward<F>(action)();
        ADD_FAILURE() << "ожидалось исключение std::system_error";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code(), win_error(expected)) << "неверный код ошибки: " << e.code().value();
    } catch (...) {
        ADD_FAILURE() << "брошено исключение не того типа, ожидался std::system_error";
    }
}

std::string pattern(std::size_t size) {
    std::string s(size, '\0');
    for (std::size_t i = 0; i < size; ++i) {
        s[i] = static_cast<char>((i * 131 + i / 251) & 0xFF);  // есть и нулевые байты
    }
    return s;
}

// ============================================================================
// Фикстура: временный каталог + проверка утечек дескрипторов
// ============================================================================

class FileTest : public ::testing::Test {
protected:
    void SetUp() override {
        hook::reset();
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        dir_ = fs::temp_directory_path() / (std::string("file_test_") + info->name());
        std::error_code ec;
        fs::remove_all(dir_, ec);
        ASSERT_TRUE(fs::create_directories(dir_));
        baseline_handles_ = count_handles();
    }

    void TearDown() override {
        hook::reset();
        EXPECT_EQ(count_handles(), baseline_handles_) << "утечка дескриптора";
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }

    // Вспомогательные файлы пишем и читаем напрямую через WinAPI,
    // чтобы не зависеть от того, как стандартная библиотека открывает пути.
    fs::path make(const fs::path& name, std::string_view content) {
        const fs::path p = dir_ / name;
        HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        EXPECT_NE(h, INVALID_HANDLE_VALUE) << "не удалось создать " << p.string();
        if (h == INVALID_HANDLE_VALUE) return p;
        std::size_t done = 0;
        while (done < content.size()) {
            DWORD n = 0;
            const DWORD want = static_cast<DWORD>(std::min<std::size_t>(content.size() - done, 1u << 20));
            if (!WriteFile(h, content.data() + done, want, &n, nullptr)) break;
            done += n;
        }
        CloseHandle(h);
        EXPECT_EQ(done, content.size());
        return p;
    }

    static std::string contents(const fs::path& p) {
        HANDLE h = CreateFileW(p.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return "<не удалось открыть файл>";
        std::string out;
        char buf[65536];
        DWORD n = 0;
        while (ReadFile(h, buf, sizeof buf, &n, nullptr) && n > 0) {
            out.append(buf, n);
        }
        CloseHandle(h);
        return out;
    }

    fs::path dir_;
    DWORD baseline_handles_ = 0;
};

using FileDeathTest = FileTest;

// ============================================================================
// open / try_open
// ============================================================================

TEST_F(FileTest, OpenExistingFile) {
    const auto p = make("a.txt", "hello");
    File f = File::open(p, kRead, OPEN_EXISTING);
    EXPECT_TRUE(f.is_open());
    EXPECT_EQ(read_n(f, 100), "hello");
}

TEST_F(FileTest, OpenNonAsciiPath) {
    const auto p = make(fs::path(u8"файл_ünï.txt"), "wide");
    File f = File::open(p, kRead, OPEN_EXISTING);
    EXPECT_EQ(read_n(f, 100), "wide") << "путь нужно передавать в CreateFileW как UTF-16";
}

TEST_F(FileTest, OpenMissingFileThrows) {
    expect_system_error([&] { (void)File::open(dir_ / "missing", kRead, OPEN_EXISTING); },
                        ERROR_FILE_NOT_FOUND);
}

TEST_F(FileTest, OpenCreateNewOnExistingFileThrows) {
    const auto p = make("a.txt", "x");
    expect_system_error([&] { (void)File::open(p, kWrite, CREATE_NEW); }, ERROR_FILE_EXISTS);
    EXPECT_EQ(contents(p), "x");
}

TEST_F(FileTest, OpenCreateAlwaysTruncates) {
    const auto p = make("a.txt", "old content");
    { File f = File::open(p, kWrite, CREATE_ALWAYS); f.write_all(bytes("new")); }
    EXPECT_EQ(contents(p), "new");
}

TEST_F(FileTest, TryOpenSuccess) {
    const auto p = make("a.txt", "data");
    auto r = File::try_open(p, kRead, OPEN_EXISTING);
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->is_open());
    EXPECT_EQ(read_n(*r, 100), "data");
}

TEST_F(FileTest, TryOpenReturnsErrorInsteadOfThrowing) {
    std::expected<File, std::error_code> r = File::try_open(dir_ / "missing", kRead, OPEN_EXISTING);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), win_error(ERROR_FILE_NOT_FOUND));
    EXPECT_EQ(r.error().category(), std::system_category())
        << "для GetLastError() нужна std::system_category()";
}

TEST_F(FileTest, TryOpenReportsFileExists) {
    const auto p = make("a.txt", "x");
    auto r = File::try_open(p, kWrite, CREATE_NEW);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), win_error(ERROR_FILE_EXISTS));
}

// ============================================================================
// Дескриптор не наследуется дочерними процессами
// ============================================================================

TEST_F(FileTest, OpenHandleIsNotInheritable) {
    const auto p = make("a.txt", "x");
    File f = File::open(p, kRead, OPEN_EXISTING);
    const auto h = find_handle(p);
    ASSERT_TRUE(h.has_value());
    EXPECT_FALSE(is_inheritable(*h)) << "open: нужен bInheritHandle = FALSE";
}

TEST_F(FileTest, TryOpenHandleIsNotInheritable) {
    const auto p = make("a.txt", "x");
    auto r = File::try_open(p, kRead, OPEN_EXISTING);
    ASSERT_TRUE(r.has_value());
    const auto h = find_handle(p);
    ASSERT_TRUE(h.has_value());
    EXPECT_FALSE(is_inheritable(*h)) << "try_open: нужен bInheritHandle = FALSE";
}

TEST_F(FileTest, ReopenHandleIsNotInheritable) {
    const auto a = make("a.txt", "a");
    const auto b = make("b.txt", "b");
    File f = File::open(a, kRead, OPEN_EXISTING);
    do_reopen(f, b, kRead);
    const auto h = find_handle(b);
    ASSERT_TRUE(h.has_value());
    EXPECT_FALSE(is_inheritable(*h)) << "reopen: нужен bInheritHandle = FALSE";
}

// ============================================================================
// Перемещение и swap
// ============================================================================

TEST_F(FileTest, MoveConstructTransfersOwnership) {
    const auto p = make("a.txt", "abc");
    File a = File::open(p, kRead, OPEN_EXISTING);
    File b = std::move(a);
    EXPECT_FALSE(a.is_open()) << "после перемещения источник должен быть закрыт";  // NOLINT(bugprone-use-after-move)
    EXPECT_TRUE(b.is_open());
    EXPECT_EQ(read_n(b, 10), "abc");
}

TEST_F(FileTest, MovedFromObjectDoesNotCloseHandle) {
    REQUIRE_CLOSE_HOOK();
    const auto p = make("a.txt", "");
    {
        std::optional<File> a(File::open(p, kWrite, OPEN_EXISTING));
        const auto h = find_handle(p);
        ASSERT_TRUE(h.has_value());
        hook::target = *h;

        File b = std::move(*a);
        a.reset();  // уничтожаем источник

        EXPECT_EQ(hook::close_calls.load(), 0)
            << "деструктор перемещённого объекта закрыл чужой дескриптор";
        EXPECT_NO_THROW(b.write_all(bytes("still works")));
    }
    EXPECT_EQ(contents(p), "still works");
}

TEST_F(FileTest, MoveAssignClosesOldHandle) {
    const auto pa = make("a.txt", "AAA");
    const auto pb = make("b.txt", "BBB");
    File a = File::open(pa, kRead, OPEN_EXISTING);
    File b = File::open(pb, kRead, OPEN_EXISTING);

    b = std::move(a);

    EXPECT_FALSE(find_handle(pb).has_value()) << "старый дескриптор b не закрыт при перемещающем присваивании";
    EXPECT_FALSE(a.is_open());  // NOLINT(bugprone-use-after-move)
    EXPECT_TRUE(b.is_open());
    EXPECT_EQ(read_n(b, 10), "AAA");
}

TEST_F(FileTest, MoveAssignToMovedFromObject) {
    const auto pa = make("a.txt", "AAA");
    const auto pb = make("b.txt", "BBB");
    File a = File::open(pa, kRead, OPEN_EXISTING);
    File b = File::open(pb, kRead, OPEN_EXISTING);
    File c = std::move(a);
    a = std::move(b);
    EXPECT_TRUE(a.is_open());
    EXPECT_EQ(read_n(a, 10), "BBB");
    EXPECT_EQ(read_n(c, 10), "AAA");
}

TEST_F(FileTest, SelfMoveAssignKeepsFileUsable) {
    const auto p = make("a.txt", "self");
    File f = File::open(p, kRead, OPEN_EXISTING);
    File& alias = f;
    f = std::move(alias);
    EXPECT_TRUE(f.is_open()) << "самоприсваивание закрыло файл";
    EXPECT_EQ(read_n(f, 10), "self");
}

TEST_F(FileTest, SwapExchangesFiles) {
    const auto pa = make("a.txt", "AAA");
    const auto pb = make("b.txt", "BBB");
    File a = File::open(pa, kRead, OPEN_EXISTING);
    File b = File::open(pb, kRead, OPEN_EXISTING);
    a.swap(b);
    EXPECT_EQ(read_n(a, 10), "BBB");
    EXPECT_EQ(read_n(b, 10), "AAA");
}

TEST_F(FileTest, SwapWithClosedFile) {
    const auto p = make("a.txt", "AAA");
    File a = File::open(p, kRead, OPEN_EXISTING);
    File b = File::open(p, kRead, OPEN_EXISTING);
    b.close();
    a.swap(b);
    EXPECT_FALSE(a.is_open());
    EXPECT_TRUE(b.is_open());
    EXPECT_EQ(read_n(b, 10), "AAA");
}

TEST_F(FileTest, SelfSwapIsHarmless) {
    const auto p = make("a.txt", "AAA");
    File a = File::open(p, kRead, OPEN_EXISTING);
    a.swap(a);
    EXPECT_TRUE(a.is_open());
    EXPECT_EQ(read_n(a, 10), "AAA");
}

TEST_F(FileTest, StdSwapWorks) {
    const auto pa = make("a.txt", "AAA");
    const auto pb = make("b.txt", "BBB");
    File a = File::open(pa, kRead, OPEN_EXISTING);
    File b = File::open(pb, kRead, OPEN_EXISTING);
    using std::swap;
    swap(a, b);
    EXPECT_EQ(read_n(a, 10), "BBB");
    EXPECT_EQ(read_n(b, 10), "AAA");
}

// ============================================================================
// read
// ============================================================================

TEST_F(FileTest, ReadAdvancesPositionAndReturnsZeroAtEof) {
    const auto p = make("a.txt", "hello world");
    File f = File::open(p, kRead, OPEN_EXISTING);
    EXPECT_EQ(read_n(f, 5), "hello");
    EXPECT_EQ(read_n(f, 100), " world");
    EXPECT_EQ(read_n(f, 100), "") << "в конце файла read должен вернуть 0";
}

TEST_F(FileTest, ReadIntoEmptyBufferReturnsZero) {
    const auto p = make("a.txt", "data");
    File f = File::open(p, kRead, OPEN_EXISTING);
    EXPECT_EQ(f.read({}), 0u);
    EXPECT_EQ(read_n(f, 10), "data") << "чтение в пустой буфер не должно сдвигать позицию";
}

TEST_F(FileTest, ReadFailureThrowsAndKeepsFileOpen) {
    const auto p = make("a.txt", "");
    {
        File f = File::open(p, kWrite, OPEN_EXISTING);
        expect_system_error([&] { (void)read_n(f, 10); }, ERROR_ACCESS_DENIED);
        EXPECT_TRUE(f.is_open()) << "базовая гарантия: после ошибки объект рабочий";
        EXPECT_NO_THROW(f.write_all(bytes("ok")));
    }
    EXPECT_EQ(contents(p), "ok");
}

// ============================================================================
// write_all
// ============================================================================

TEST_F(FileTest, WriteAllWritesEverything) {
    const auto p = dir_ / "out.txt";
    {
        File f = File::open(p, kWrite, CREATE_ALWAYS);
        f.write_all(bytes("first "));
        f.write_all(bytes("second"));
    }
    EXPECT_EQ(contents(p), "first second");
}

TEST_F(FileTest, WriteAllEmptyIsNoop) {
    const auto p = make("a.txt", "keep");
    {
        File f = File::open(p, kWrite, OPEN_EXISTING);
        EXPECT_NO_THROW(f.write_all({}));
    }
    EXPECT_EQ(contents(p), "keep");
}

TEST_F(FileTest, WriteAllLargeBuffer) {
    const auto p = dir_ / "big.bin";
    const std::string data = pattern(4 * 1024 * 1024 + 7);
    {
        File f = File::open(p, kWrite, CREATE_ALWAYS);
        f.write_all(bytes(data));
    }
    EXPECT_TRUE(contents(p) == data) << "содержимое большого файла не совпадает";
}

TEST_F(FileTest, WriteAllHandlesShortWrites) {
    REQUIRE_WRITE_HOOK();
    const auto p = dir_ / "out.bin";
    const std::string data = pattern(1000);
    int calls = 0;
    {
        File f = File::open(p, kWrite, CREATE_ALWAYS);
        const auto h = find_handle(p);
        ASSERT_TRUE(h.has_value());

        hook::target = *h;
        hook::write_max_chunk = 3;  // каждый WriteFile пишет не больше 3 байт
        f.write_all(bytes(data));
        calls = hook::write_calls.load();
        hook::reset();
    }
    EXPECT_GE(calls, 334) << "write_all должен писать через WriteFile в цикле";
    EXPECT_TRUE(contents(p) == data) << "write_all не дописал данные после неполной записи";
}

TEST_F(FileTest, WriteAllRealErrorThrowsAndKeepsFileUsable) {
    REQUIRE_WRITE_HOOK();
    const auto p = dir_ / "out.txt";
    {
        File f = File::open(p, kWrite, CREATE_ALWAYS);
        const auto h = find_handle(p);
        ASSERT_TRUE(h.has_value());

        hook::target = *h;
        hook::write_max_chunk = 4;
        hook::write_fail_at = 3;  // первые два вызова пишут по 4 байта, третий падает
        hook::write_fail_error = ERROR_DISK_FULL;
        expect_system_error([&] { f.write_all(bytes("abcdefghijkl")); }, ERROR_DISK_FULL);
        hook::reset();

        // Базовая гарантия: часть данных могла записаться, но объект рабочий.
        EXPECT_TRUE(f.is_open());
        EXPECT_NO_THROW(f.write_all(bytes("!")));
    }
    EXPECT_EQ(contents(p), "abcdefgh!");
}

TEST_F(FileTest, WriteAllToReadOnlyFileThrows) {
    const auto p = make("a.txt", "orig");
    {
        File f = File::open(p, kRead, OPEN_EXISTING);
        expect_system_error([&] { f.write_all(bytes("x")); }, ERROR_ACCESS_DENIED);
        EXPECT_TRUE(f.is_open());
        EXPECT_EQ(read_n(f, 10), "orig");
    }
    EXPECT_EQ(contents(p), "orig");
}

// ============================================================================
// read_all
// ============================================================================

TEST_F(FileTest, ReadAllReturnsWholeFile) {
    const auto p = make("a.txt", "line1\nline2\n");
    const File f = File::open(p, kRead, OPEN_EXISTING);
    EXPECT_EQ(f.read_all(), "line1\nline2\n") << "read_all не должен менять байты (\\n остаётся \\n)";
}

TEST_F(FileTest, ReadAllOfEmptyFile) {
    const auto p = make("empty.txt", "");
    const File f = File::open(p, kRead, OPEN_EXISTING);
    EXPECT_EQ(f.read_all(), "");
}

TEST_F(FileTest, ReadAllLargeBinaryFile) {
    const std::string data = pattern(3 * 1024 * 1024 + 17);
    const auto p = make("big.bin", data);
    const File f = File::open(p, kRead, OPEN_EXISTING);
    const std::string got = f.read_all();
    EXPECT_EQ(got.size(), data.size());
    EXPECT_TRUE(got == data) << "содержимое не совпадает (нулевые байты тоже должны читаться)";
}

TEST_F(FileTest, ReadAllDoesNotMovePosition) {
    const auto p = make("a.txt", "0123456789");
    File f = File::open(p, kRead, OPEN_EXISTING);
    EXPECT_EQ(read_n(f, 3), "012");
    EXPECT_EQ(f.read_all(), "0123456789") << "read_all читает файл целиком, с начала";
    EXPECT_EQ(read_n(f, 3), "345") << "read_all не восстановил позицию (SetFilePointerEx)";
}

TEST_F(FileTest, ReadAllCalledTwiceGivesSameResult) {
    const auto p = make("a.txt", "twice");
    const File f = File::open(p, kRead, OPEN_EXISTING);
    EXPECT_EQ(f.read_all(), "twice");
    EXPECT_EQ(f.read_all(), "twice");
}

TEST_F(FileTest, ReadAllFailureIsStrong) {
    const auto p = dir_ / "out.txt";
    {
        File f = File::open(p, kWrite, CREATE_ALWAYS);
        f.write_all(bytes("abc"));  // позиция = 3

        expect_system_error([&] { (void)f.read_all(); }, ERROR_ACCESS_DENIED);

        // Строгая гарантия: файл открыт, позиция осталась 3.
        EXPECT_TRUE(f.is_open());
        f.write_all(bytes("X"));
    }
    EXPECT_EQ(contents(p), "abcX") << "после неудачного read_all изменилась позиция в файле";
}

// ============================================================================
// reopen
// ============================================================================

TEST_F(FileTest, ReopenSwitchesToNewFileAndClosesOld) {
    const auto pa = make("a.txt", "AAA");
    const auto pb = make("b.txt", "BBB");
    File f = File::open(pa, kRead, OPEN_EXISTING);
    const DWORD before = count_handles();

    do_reopen(f, pb, kRead);

    EXPECT_TRUE(f.is_open());
    EXPECT_EQ(read_n(f, 10), "BBB");
    EXPECT_FALSE(find_handle(pa).has_value()) << "старый файл не закрыт";
    EXPECT_EQ(count_handles(), before);
}

TEST_F(FileTest, ReopenFailureIsStrong) {
    const auto p = make("a.txt", "0123456789");
    File f = File::open(p, kRead, OPEN_EXISTING);
    EXPECT_EQ(read_n(f, 4), "0123");

    expect_system_error([&] { do_reopen(f, dir_ / "missing", kRead); }, ERROR_FILE_NOT_FOUND);

    // Строгая гарантия: тот же файл, та же позиция.
    EXPECT_TRUE(f.is_open());
    EXPECT_TRUE(find_handle(p).has_value());
    EXPECT_EQ(read_n(f, 4), "4567");
}

TEST_F(FileTest, ReopenSameFileResetsPosition) {
    const auto p = make("a.txt", "abcdef");
    File f = File::open(p, kRead, OPEN_EXISTING);
    EXPECT_EQ(read_n(f, 3), "abc");
    do_reopen(f, p, kRead);
    EXPECT_EQ(read_n(f, 3), "abc");
}

TEST_F(FileTest, ReopenClosedFile) {
    const auto p = make("a.txt", "again");
    File f = File::open(p, kRead, OPEN_EXISTING);
    f.close();
    do_reopen(f, p, kRead);
    EXPECT_TRUE(f.is_open());
    EXPECT_EQ(read_n(f, 10), "again");
}

TEST_F(FileTest, ReopenMovedFromFile) {
    const auto pa = make("a.txt", "AAA");
    const auto pb = make("b.txt", "BBB");
    File a = File::open(pa, kRead, OPEN_EXISTING);
    File b = std::move(a);
    do_reopen(a, pb, kRead);  // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(read_n(a, 10), "BBB");
    EXPECT_EQ(read_n(b, 10), "AAA");
}

// ============================================================================
// close и деструктор
// ============================================================================

TEST_F(FileTest, CloseClosesHandle) {
    const auto p = make("a.txt", "x");
    File f = File::open(p, kRead, OPEN_EXISTING);
    f.close();
    EXPECT_FALSE(f.is_open());
    EXPECT_FALSE(find_handle(p).has_value());
    EXPECT_EQ(count_handles(), baseline_handles_);
}

TEST_F(FileTest, DestructorClosesHandle) {
    const auto p = make("a.txt", "x");
    { File f = File::open(p, kRead, OPEN_EXISTING); }
    EXPECT_FALSE(find_handle(p).has_value());
}

TEST_F(FileTest, CloseErrorThrowsButFileIsClosed) {
    REQUIRE_CLOSE_HOOK();
    const auto p = make("a.txt", "x");
    File f = File::open(p, kRead, OPEN_EXISTING);
    const auto h = find_handle(p);
    ASSERT_TRUE(h.has_value());

    hook::target = *h;
    hook::close_fail_error = ERROR_IO_DEVICE;
    expect_system_error([&] { f.close(); }, ERROR_IO_DEVICE);
    const int calls = hook::close_calls.load();
    hook::reset();

    EXPECT_EQ(calls, 1);
    EXPECT_FALSE(f.is_open()) << "после close файл закрыт, даже если CloseHandle вернул ошибку";
    EXPECT_FALSE(find_handle(p).has_value());
}

TEST_F(FileTest, DestructorAfterCloseDoesNotCloseAgain) {
    REQUIRE_CLOSE_HOOK();
    const auto p = make("a.txt", "x");
    std::optional<File> f(File::open(p, kRead, OPEN_EXISTING));
    const auto h = find_handle(p);
    ASSERT_TRUE(h.has_value());

    hook::target = *h;
    f->close();
    f.reset();  // деструктор
    EXPECT_EQ(hook::close_calls.load(), 1) << "дескриптор закрыт повторно";
}

TEST_F(FileTest, DestructorAfterFailedCloseDoesNotCloseAgain) {
    REQUIRE_CLOSE_HOOK();
    const auto p = make("a.txt", "x");
    std::optional<File> f(File::open(p, kRead, OPEN_EXISTING));
    const auto h = find_handle(p);
    ASSERT_TRUE(h.has_value());

    hook::target = *h;
    hook::close_fail_error = ERROR_IO_DEVICE;
    EXPECT_THROW(f->close(), std::system_error);
    hook::close_fail_error = 0;
    f.reset();
    EXPECT_EQ(hook::close_calls.load(), 1)
        << "после ошибки CloseHandle повторный вызов в деструкторе может закрыть чужой дескриптор";
}

TEST_F(FileTest, CloseOnClosedFileKeepsItClosed) {
    const auto p = make("a.txt", "x");
    File f = File::open(p, kRead, OPEN_EXISTING);
    f.close();
    // Повторный close задание не описывает: можно ничего не делать или бросить,
    // но файл должен остаться закрытым, а программа — живой.
    try { f.close(); } catch (const std::system_error&) {}
    EXPECT_FALSE(f.is_open());
}

TEST_F(FileDeathTest, DestructorSwallowsCloseError) {
    REQUIRE_CLOSE_HOOK();
    const auto p = make("a.txt", "x");
    // Тело выполняется в дочернем процессе: если деструктор бросит,
    // вызовется std::terminate, и код выхода будет не 0.
    EXPECT_EXIT(
        {
            {
                File f = File::open(p, kRead, OPEN_EXISTING);
                hook::target = *find_handle(p);
                hook::close_fail_error = ERROR_IO_DEVICE;
            }
            std::_Exit(hook::close_calls.load() == 1 ? 0 : 2);
        },
        ::testing::ExitedWithCode(0), "");
}

}  // namespace
