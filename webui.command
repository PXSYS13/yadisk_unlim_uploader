#!/bin/bash
cd -- "$(dirname -- "$0")" || exit 1
/bin/bash ./webui.sh
status=$?
echo
echo "Программа остановлена. Это окно можно закрыть."
exit "$status"
