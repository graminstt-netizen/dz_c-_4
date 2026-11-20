cmake -S . -B build	     ### Первый запуск или изменение CMakeLists.txt
cmake --build build --config Debug	    ### Каждый раз, когда пересобираешь проект
ctest --test-dir build -C Debug --output-on-failure	     ### Каждый раз, когда проверяешь тесты