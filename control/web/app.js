import { createManagedUI } from "./managed.js";
const dictionary = {
  services: ["Свои сервисы", "Own services"],
  storages: ["Хранилища", "Storage"],
  edition: ["Управление защитой", "Recovery control"],
  dashboard: ["Обзор", "Overview"],
  restore: ["Восстановление", "Recovery"],
  nodes: ["Серверы", "Servers"],
  history: ["Операции", "Operations"],
  settings: ["Настройки", "Settings"],
  setup: ["Настройка защиты", "Protection setup"],
  connected: ["Связь установлена", "Connected"],
  connectionLost: ["Нет связи с панелью", "Panel unavailable"],
  refresh: ["Обновить", "Refresh"],
  logout: ["Выйти", "Sign out"],
  version: ["Версия", "Version"],
  sidebarTitle: ["Данные должны возвращаться.", "Data should come back."],
  sidebarText: [
    "Копия становится полезной после проверки восстановления.",
    "A backup becomes useful when recovery has been checked.",
  ],
  scope: [
    "Свои сервисы Compose и тестовый PostgreSQL + файлы.",
    "Compose services and the bundled PostgreSQL + files demo.",
  ],
  authTitle: ["Сохранить данные.", "Keep your data."],
  authAccent: ["Вернуть сервис.", "Bring services back."],
  authLead: [
    "Резервные копии, проверка восстановления и состояние площадок в одном месте.",
    "Backups, recovery checks and site state in one place.",
  ],
  authFooter: [
    "Открытый исходный код · Apache 2.0",
    "Open source · Apache 2.0",
  ],
  loginTitle: ["Вход в панель", "Sign in to your panel"],
  loginHelp: [
    "Пароль администратора находится в закрытом комплекте восстановления.",
    "The administrator password is in your private recovery kit.",
  ],
  password: ["Пароль", "Password"],
  signIn: ["Войти", "Sign in"],
  passwordPlaceholder: ["Пароль администратора", "Administrator password"],
  authNote: [
    "Управление доступно только после входа. Пароль и учетные данные серверов не передаются другим посетителям.",
    "Management requires sign-in. Your password and server credentials are not shared with other visitors.",
  ],
  changePassword: ["Изменить пароль", "Change password"],
  changePasswordTitle: ["Ваш собственный пароль", "A password of your own"],
  changePasswordHelp: [
    "Установите новый пароль администратора перед управлением защитой.",
    "Set a new administrator password before managing protection.",
  ],
  currentPassword: ["Текущий пароль", "Current password"],
  newPassword: ["Новый пароль", "New password"],
  repeatPassword: ["Повторите новый пароль", "Repeat new password"],
  passwordHelp: [
    "Не менее 16 символов. Используйте уникальный пароль.",
    "At least 16 characters. Use a unique password.",
  ],
  passwordMismatch: [
    "Новые пароли не совпадают.",
    "The new passwords do not match.",
  ],
  passwordChanged: ["Пароль изменен.", "Password changed."],
  controlEyebrow: ["Рабочее пространство", "Workspace"],
  dashboardTitle: ["Все площадки под наблюдением", "Keep every site in sight"],
  dashboardLead: [
    "Состояние сервиса, история копий и результаты восстановления.",
    "Service state, backup history and recovery results.",
  ],
  backupNow: ["Создать копию", "Back up now"],
  viewRecovery: ["Восстановить копию", "Recover a copy"],
  finishSetup: ["Завершить настройку", "Finish setup"],
  setupIncomplete: [
    "Настройка защиты еще не завершена. Подключите серверы и выполните первое проверенное восстановление.",
    "Protection setup is not complete. Connect your servers and run the first verified restore.",
  ],
  onlineNodes: ["Серверов на связи", "Servers online"],
  latestBackup: ["Последняя копия", "Latest backup"],
  lastRestore: ["Последняя проверка", "Last recovery check"],
  freeSpace: ["Свободное место", "Free storage"],
  noData: ["Нет данных", "No data"],
  notChecked: ["Еще не проверено", "Not checked yet"],
  notAvailable: ["Недоступно", "Unavailable"],
  ofNodes: ["из {total}", "of {total}"],
  observedSpace: ["На подключенных серверах", "Across connected servers"],
  backupAge: [
    "Возраст последней точки восстановления",
    "Age of the latest recovery point",
  ],
  restoreAge: ["Последнее успешное испытание", "Last successful exercise"],
  protectedService: ["Защищаемый сервис", "Protected service"],
  serviceName: ["Тестовый веб-сервис", "Demo web service"],
  serviceDescription: [
    "PostgreSQL, постоянные файлы, конфигурация и образы приложения.",
    "PostgreSQL, persistent files, configuration and application images.",
  ],
  primary: ["Основная площадка", "Primary site"],
  recovery: ["Площадка восстановления", "Recovery site"],
  unassigned: ["Не подключена", "Not connected"],
  healthy: ["Данные согласованы", "Data consistent"],
  unhealthy: ["Нужна проверка", "Needs attention"],
  offline: ["Нет свежих данных", "No fresh data"],
  unsupported: ["Сервис не поддерживается", "Unsupported service"],
  nodeSeen: ["Данные получены: {time}", "Observed: {time}"],
  protectionState: ["Что проверено", "What is verified"],
  backupPresent: ["Есть точка восстановления", "A recovery point exists"],
  restorePresent: [
    "Выполнено пробное восстановление",
    "A restore exercise has passed",
  ],
  nodesPresent: ["Площадки доступны", "Sites are reachable"],
  runtimeCheck: [
    "Проверка данных и условий запуска",
    "Data and runtime checks",
  ],
  automaticUnavailable: [
    "Автоматическое переключение DNS в этой версии недоступно. Публикация восстановленного сервиса требует отдельного решения.",
    "Automatic DNS failover is unavailable in this version. Publishing a restored service requires a separate decision.",
  ],
  sameHostWarning: [
    "Копия на том же сервере не защищает от его полной потери. Подключите отдельную площадку хранения.",
    "A copy on the same server cannot survive losing that server. Connect a separate storage site.",
  ],
  recentOperations: ["Последние операции", "Recent operations"],
  allOperations: ["Все операции", "All operations"],
  noOperations: ["Операций пока нет", "No operations yet"],
  noOperationsHelp: [
    "Создайте первую копию или запустите проверку восстановления.",
    "Create the first backup or run a restore check.",
  ],
  action: ["Действие", "Action"],
  site: ["Площадка", "Site"],
  status: ["Состояние", "State"],
  started: ["Начало", "Started"],
  finished: ["Завершение", "Finished"],
  duration: ["Длительность", "Duration"],
  snapshot: ["Точка восстановления", "Recovery point"],
  operationId: ["Номер операции", "Operation ID"],
  showDetails: ["Подробнее", "Details"],
  queued: ["В очереди", "Queued"],
  dispatched: ["Передано серверу", "Sent to server"],
  running: ["Выполняется", "Running"],
  succeeded: ["Завершено", "Succeeded"],
  failed: ["Ошибка", "Failed"],
  outcome_unknown: ["Результат неизвестен", "Outcome unknown"],
  jobProgress: [
    "Операция выполняется на сервере. Можно закрыть страницу: работа продолжится.",
    "The server is running this operation. You can close this page; work will continue.",
  ],
  unknownWarning: [
    "Результат операции пока не подтвержден. Повторный запуск заблокирован до выяснения фактического состояния.",
    "The outcome is not confirmed. A repeat run is blocked until the actual state is reconciled.",
  ],
  jobFinished: [
    "Операция завершена. Результаты сохранены.",
    "Operation completed. Results were saved.",
  ],
  jobFailed: [
    "Операция не завершилась успешно. Проверьте ее результат перед повтором.",
    "The operation did not succeed. Review its result before trying again.",
  ],
  backup: ["Создание копии", "Create backup"],
  verify: ["Проверка хранилища", "Verify repository"],
  "restore-check": ["Проверка восстановления", "Restore exercise"],
  "restore-preview": ["Подготовка отдельной копии", "Prepare a separate copy"],
  "remove-preview": ["Удаление проверочной копии", "Remove preview copy"],
  "set-schedule": ["Изменение расписания", "Apply backup schedule"],
  stageQueued: ["Ожидание исполнителя", "Waiting for server"],
  stageRunning: ["Выполнение и проверка результата", "Running and verifying"],
  stageCapture: [
    "Сохранение согласованных данных",
    "Capturing consistent data",
  ],
  stageTransfer: [
    "Передача зашифрованной копии",
    "Transferring encrypted backup",
  ],
  stageVerify: ["Проверка целостности", "Checking integrity"],
  stageRestore: [
    "Восстановление отдельного окружения",
    "Restoring a separate environment",
  ],
  stageChecks: [
    "Проверка приложения и данных",
    "Checking application and data",
  ],
  stageCleanup: [
    "Очистка временного окружения",
    "Cleaning up temporary environment",
  ],
  restoreEyebrow: ["Проверяемое восстановление", "Verified recovery"],
  restoreTitle: ["Вернуть сервис из копии", "Bring a service back from backup"],
  restoreLead: [
    "Выберите точную копию и площадку. Восстановление создаст отдельное окружение и сохранит работающий сервис.",
    "Choose an exact recovery point and a target site. Recovery creates a separate environment and preserves the live service.",
  ],
  chooseTarget: ["Куда восстановить", "Recovery target"],
  chooseSnapshot: ["Какую копию использовать", "Recovery point"],
  selectSnapshot: ["Выберите точку восстановления", "Select a recovery point"],
  selectNode: ["Выберите сервер", "Select a server"],
  snapshotDate: ["Время создания", "Created"],
  dataAge: ["Возраст данных", "Data age"],
  checkRestore: ["Проверить восстановление", "Run restore check"],
  retainRestore: ["Подготовить отдельную копию", "Keep a restored copy"],
  verifyRepository: ["Проверить целостность", "Verify integrity"],
  restoreExplanation: [
    "Проверка запускает приложение, сравнивает данные и ограничения контейнеров, затем удаляет временную копию. Отдельную сохраненную копию можно оставить для изучения.",
    "A restore check starts the application, compares data and container restrictions, then removes the temporary copy. A retained copy can be kept for inspection.",
  ],
  noSnapshots: ["Точек восстановления пока нет", "No recovery points yet"],
  noSnapshotsHelp: [
    "Создайте резервную копию на основной площадке и дождитесь ее появления в хранилище.",
    "Create a backup on the primary site and wait for it to appear in storage.",
  ],
  snapshotCount: [
    "Копий в доступном хранилище: {count}",
    "Available recovery points: {count}",
  ],
  previewTitle: ["Сохраненная проверочная копия", "Retained preview copy"],
  previewHelp: [
    "Копия проверена и сохранена отдельно. Публичный маршрут на нее не переключался.",
    "This copy was checked and retained separately. Public traffic has not been switched to it.",
  ],
  previewSnapshot: ["Восстановленная точка", "Restored point"],
  previewChecks: ["Выполненные проверки", "Completed checks"],
  removePreview: ["Удалить эту копию", "Remove this copy"],
  previewNone: ["Проверочная копия не подготовлена", "No retained preview yet"],
  previewUnavailable: [
    "Сведения о проверочной копии недоступны.",
    "Preview state is unavailable.",
  ],
  nodesEyebrow: ["Независимые площадки", "Independent sites"],
  nodesTitle: ["Подключенные серверы", "Connected servers"],
  nodesLead: [
    "Каждая служба сервера сама устанавливает защищенное соединение с панелью.",
    "Each host service establishes its own secure connection to the panel.",
  ],
  addNode: ["Подключить сервер", "Connect a server"],
  nodeName: ["Название сервера", "Server name"],
  nodeNamePlaceholder: [
    "Например: Основная площадка",
    "For example: Primary site",
  ],
  nodeRole: ["Назначение", "Role"],
  enrollTitle: ["Подключение сервера", "Connect a server"],
  enrollHelp: [
    "Создайте одноразовую команду подключения и выполните ее на своем сервере через существующий доступ. Пароль SSH в панель вводить не требуется.",
    "Create a one-time enrollment command and run it on your server using your existing access. No SSH password is entered into this panel.",
  ],
  createEnrollment: [
    "Получить команду подключения",
    "Create enrollment command",
  ],
  enrollmentCommand: ["Одноразовая команда", "One-time command"],
  enrollmentExpires: ["Действует до {time}", "Valid until {time}"],
  enrollmentWaiting: [
    "Ожидаем подключения сервера. Страница обновится автоматически.",
    "Waiting for the server to connect. This page will update automatically.",
  ],
  copyCommand: ["Скопировать команду", "Copy command"],
  copied: ["Скопировано", "Copied"],
  copyFailed: [
    "Не удалось скопировать автоматически. Выделите команду и скопируйте ее вручную.",
    "Could not copy automatically. Select the command and copy it manually.",
  ],
  enrollmentExpired: [
    "Срок команды истек. Создайте новую команду подключения.",
    "This command has expired. Create a new enrollment command.",
  ],
  noNodes: ["Серверы еще не подключены", "No servers connected yet"],
  noNodesHelp: [
    "Подключите первый сервер, чтобы обнаружить поддерживаемый сервис и настроить защиту.",
    "Connect your first server to discover the supported service and configure protection.",
  ],
  diskFree: ["Свободно {free} из {total}", "{free} free of {total}"],
  serviceState: ["Состояние сервиса", "Service state"],
  agentVersion: ["Версия службы", "Host service version"],
  backupSchedule: ["Расписание копирования", "Backup schedule"],
  restoreSchedule: ["Проверки восстановления", "Restore checks"],
  enabled: ["Включено", "Enabled"],
  disabled: ["Отключено", "Disabled"],
  nextRun: ["Следующий запуск: {time}", "Next run: {time}"],
  lastSeen: ["Последняя связь", "Last seen"],
  historyEyebrow: ["История действий", "Operation history"],
  historyTitle: [
    "Каждая операция с результатом",
    "Every operation has a result",
  ],
  historyLead: [
    "Запуск, ход выполнения и подтвержденный результат сохраняются после закрытия страницы.",
    "Start, progress and confirmed outcomes survive closing this page.",
  ],
  settingsEyebrow: ["Политика защиты", "Protection policy"],
  settingsTitle: ["Настроить защиту", "Configure protection"],
  settingsLead: [
    "Требования к защите и фактическое расписание сервера показаны отдельно.",
    "Protection preferences and the server’s applied schedule are shown separately.",
  ],
  profile: ["Состав защиты", "Protection profile"],
  single: ["Один сервер", "Single server"],
  singleHelp: [
    "Копии и проверка восстановления. Для потери сервера нужно отдельное хранилище.",
    "Backups and restore checks. Surviving host loss requires separate storage.",
  ],
  pair_assisted: ["Две площадки", "Two sites"],
  pairHelp: [
    "Основной сервис и площадка для отдельного восстановления. Переключение подтверждает администратор.",
    "A primary service and a separate recovery site. An administrator confirms switching.",
  ],
  backupInterval: ["Как часто создавать копии", "Backup frequency"],
  "15min": ["Каждые 15 минут", "Every 15 minutes"],
  hourly: ["Каждый час", "Hourly"],
  daily: ["Каждый день", "Daily"],
  savePreferences: ["Сохранить требования", "Save preferences"],
  settingsSaved: [
    "Требования сохранены. Расписание на сервере применяется отдельной операцией.",
    "Preferences saved. Applying the host schedule is a separate operation.",
  ],
  applySchedule: ["Применить расписание", "Apply schedule"],
  actualSchedule: ["Фактическое расписание", "Applied schedule"],
  scheduleHelp: [
    "Изменение будет подтверждено только после ответа службы сервера.",
    "The change is confirmed only after the host service reports its result.",
  ],
  rerunSetup: ["Открыть мастер настройки", "Open setup wizard"],
  account: ["Доступ администратора", "Administrator access"],
  setupEyebrow: ["Начальная настройка", "Initial setup"],
  setupTitle: [
    "Защита, проверенная на практике",
    "Protection that has been tested",
  ],
  setupLead: [
    "Подключите площадки, выберите требования и проверьте настоящее восстановление.",
    "Connect your sites, choose preferences and test a real restore.",
  ],
  stepNodes: ["Серверы", "Servers"],
  stepPolicy: ["Требования", "Preferences"],
  stepVerify: ["Испытание", "Exercise"],
  stepReady: ["Готовность", "Readiness"],
  back: ["Назад", "Back"],
  next: ["Продолжить", "Continue"],
  nodesStepHelp: [
    "Для двух площадок нужны подключенные основной сервер и сервер восстановления. Один сервер можно настроить отдельно.",
    "Two-site protection needs a connected primary and recovery server. A single server can be configured separately.",
  ],
  policyStepHelp: [
    "Частота копирования определяет возможный возраст восстановленных данных. Репликация базы в этой версии не выполняется.",
    "Backup frequency affects how old recovered data may be. This version does not replicate the database.",
  ],
  verifyStepTitle: [
    "Проверим полный путь",
    "Exercise the complete recovery path",
  ],
  verifyStepHelp: [
    "Сначала создайте новую копию основной площадки. Затем восстановите именно эту копию на выбранном сервере.",
    "First create a new backup of the primary site. Then restore that exact recovery point on the chosen server.",
  ],
  firstBackup: ["1. Создать первую копию", "1. Create the first backup"],
  firstRestore: ["2. Проверить эту копию", "2. Check that recovery point"],
  backupNeeded: [
    "Ожидается успешная новая копия основной площадки.",
    "A successful new primary backup is required.",
  ],
  restoreNeeded: [
    "Ожидается восстановление той же точки на целевой площадке.",
    "That same recovery point must be restored on the target site.",
  ],
  checkPassed: ["Проверка завершена успешно", "Check passed"],
  waitingOperation: [
    "Дождитесь завершения операции.",
    "Wait for the operation to finish.",
  ],
  readyTitle: ["Можно завершить настройку", "Ready to finish setup"],
  readyHelp: [
    "Панель повторно проверит связь с площадками и результаты операций. Успех означает проверку этого сервиса, а не всех возможных отказов.",
    "The panel will recheck site connectivity and operation results. Success verifies this service, not every possible failure.",
  ],
  completeSetup: ["Завершить настройку", "Complete setup"],
  setupCompleted: ["Настройка защиты завершена.", "Protection setup complete."],
  setupNotReady: [
    "Для завершения нужны успешная копия и проверка восстановления именно этой точки.",
    "Completion requires a successful backup and a restore check of that exact recovery point.",
  ],
  planTitle: ["Подтвердите действие", "Review this operation"],
  planExpires: ["План действителен до {time}", "Plan valid until {time}"],
  planConfirm: ["Запустить операцию", "Start operation"],
  cancel: ["Отмена", "Cancel"],
  close: ["Закрыть", "Close"],
  confirmPause: [
    "Создание копии ненадолго остановит веб-процесс тестового сервиса. Затем он будет запущен снова.",
    "Capturing this backup briefly pauses the demo web process. It will then be started again.",
  ],
  confirmIsolated: [
    "Будет создано отдельное окружение. Работающие данные и публичный маршрут сохранятся.",
    "A separate environment will be created. Live data and public routing will be preserved.",
  ],
  confirmRemove: [
    "Будет удалена только проверочная копия, созданная этой системой. Сервис и резервные копии в хранилище сохранятся.",
    "Only the preview created by this system will be removed. The service and repository backups will be preserved.",
  ],
  confirmSchedule: [
    "Будет изменено расписание резервирования на выбранной основной площадке.",
    "The backup schedule on the selected primary site will change.",
  ],
  confirmVerify: [
    "Будет прочитано и проверено содержимое хранилища. Данные сервиса останутся без изменений.",
    "Repository contents will be read and checked. Service data will remain unchanged.",
  ],
  operationQueued: [
    "Операция принята. Результат появится в истории.",
    "Operation accepted. Its result will appear in history.",
  ],
  loading: ["Загрузка…", "Loading…"],
  working: ["Выполняется…", "Working…"],
  checks: ["Проверки", "Checks"],
  check_database_values: ["Значения записей базы", "Database record values"],
  check_file_sha256: ["Контрольная сумма файла", "File checksum"],
  check_application_http: [
    "Ответ приложения HTTP",
    "Application HTTP response",
  ],
  check_app_version: ["Версия приложения", "Application version"],
  check_image_ids: ["Идентификаторы образов", "Image identity"],
  check_fresh_mounts: ["Отдельные каталоги данных", "Fresh data mounts"],
  check_runtime_restrictions: [
    "Ограничения контейнеров",
    "Container restrictions",
  ],
  check_generic: ["Проверка сервиса", "Service check"],
  error_generic: [
    "Не удалось выполнить запрос. Обновите состояние и повторите попытку.",
    "The request could not be completed. Refresh the state and try again.",
  ],
  error_network: [
    "Панель недоступна. Проверьте соединение; уже запущенная операция продолжает выполняться на сервере.",
    "The panel is unreachable. Check your connection; an operation already started continues on the server.",
  ],
  error_invalid_credentials: ["Неверный пароль.", "Incorrect password."],
  error_unauthorized: [
    "Сеанс завершен. Войдите снова.",
    "Your session has ended. Sign in again.",
  ],
  error_rate_limited: [
    "Слишком много попыток. Подождите и попробуйте снова.",
    "Too many attempts. Wait before trying again.",
  ],
  error_csrf: [
    "Защитный код сеанса устарел. Обновите страницу.",
    "The session security code is stale. Refresh this page.",
  ],
  error_revision_conflict: [
    "Настройки изменились. Обновите страницу и проверьте новый план.",
    "Settings changed. Refresh and review a new plan.",
  ],
  error_plan_expired: [
    "Срок плана истек. Подготовьте действие заново.",
    "This plan expired. Prepare the operation again.",
  ],
  error_plan_stale: [
    "Состояние изменилось. Подготовьте новый план операции.",
    "The state changed. Prepare a new operation plan.",
  ],
  error_node_offline: [
    "Нет свежей связи с сервером. Дождитесь подключения.",
    "No fresh connection to this server. Wait for it to reconnect.",
  ],
  error_unsupported_service: [
    "На этом сервере не обнаружен поддерживаемый сервис.",
    "The supported service was not found on this server.",
  ],
  error_invalid_snapshot: [
    "Выбранная точка восстановления недоступна. Обновите список копий.",
    "This recovery point is unavailable. Refresh the snapshot list.",
  ],
  error_setup_not_ready: [
    "Настройку нельзя завершить: нужны доступные площадки, успешная копия и ее проверенное восстановление.",
    "Setup cannot finish yet: connected sites, a successful backup and its verified restore are required.",
  ],
  error_operation_busy: [
    "Предыдущая операция еще выполняется или ее результат неизвестен.",
    "A previous operation is still running or its outcome is unknown.",
  ],
  error_preview_exists: [
    "Проверочная копия уже существует. Сначала проверьте ее состояние и удалите ее отдельным действием.",
    "A preview already exists. Review its state and remove it as a separate operation first.",
  ],
  error_password_too_short: [
    "Новый пароль должен содержать не менее 16 символов.",
    "The new password must contain at least 16 characters.",
  ],
  error_invalid_request: [
    "Проверьте заполненные поля.",
    "Check the entered values.",
  ],
  error_wrong_password: [
    "Текущий пароль неверен.",
    "The current password is incorrect.",
  ],
  error_not_found: [
    "Запись не найдена. Обновите состояние.",
    "This record was not found. Refresh the state.",
  ],
  alert_node_offline: [
    "Сервер не передает свежие данные.",
    "A server is not reporting fresh data.",
  ],
  alert_backup_missing: [
    "Нет подтвержденной резервной копии.",
    "No confirmed backup is available.",
  ],
  alert_backup_stale: [
    "Последняя копия устарела.",
    "The latest backup is stale.",
  ],
  alert_restore_missing: [
    "Нет успешной проверки восстановления.",
    "No successful restore check is available.",
  ],
  alert_restore_stale: [
    "Проверка восстановления устарела.",
    "The last restore check is stale.",
  ],
  alert_disk_low: [
    "На сервере остается мало свободного места.",
    "A server is low on disk space.",
  ],
  alert_operation_unknown: [
    "Результат операции неизвестен и требует проверки.",
    "An operation outcome is unknown and needs investigation.",
  ],
  alert_unsupported: [
    "Обнаружен неподдерживаемый сервис.",
    "An unsupported service was found.",
  ],
  alert_generic: [
    "Есть условие защиты, которое требует проверки.",
    "A protection condition needs attention.",
  ],
};
Object.assign(dictionary, {
  orphanInventorySettled: [
    "Полная сверка уже не требуется. Состояние обновлено.",
    "A full inspection is no longer required. The state has been refreshed.",
  ],
  orphanInventoryTitle: [
    "Нужна полная сверка сервера",
    "Full host inspection required",
  ],
  orphanInventoryHelp: [
    "Состояние части операций сервера пока не подтверждено. Запросите полную сверку перед продолжением.",
    "The state of some host operations is still unconfirmed. Request a full inspection before continuing.",
  ],
  orphanInventoryInspect: [
    "Проверить все операции сервера",
    "Inspect host operation inventory",
  ],
  orphanInventoryConfirm: [
    "Служба сверит локальный журнал операций с фактическим состоянием процессов. Исходные действия повторно не запускаются. Допускается очистка только временных копий, созданных этой системой. Исходный сервис перезапускаться не будет.",
    "The host service will compare its local operation records with the actual process state. The original actions will not run again. Only temporary copies owned by this system may be cleaned up. The original service will not be restarted.",
  ],
  orphanTitle: [
    "Неподтвержденные операции сервера",
    "Unconfirmed server operations",
  ],
  orphanHelp: [
    "Сервер сообщает об операции, которая не согласуется с текущим каталогом. Новые изменения приостановлены до проверки фактического состояния.",
    "A server reports work that does not match the current catalog. New changes are paused until its actual state is inspected.",
  ],
  orphanInspect: ["Проверить фактическое состояние", "Inspect actual state"],
  orphanInspectHelp: [
    "Служба проверит сохраненный результат и состояние процессов. Исходное действие повторно не запускается. Допускается очистка только временной копии, созданной этой системой. Исходный сервис перезапускаться не будет.",
    "The host service will inspect its saved outcome and running processes. The original action will not run again. Only a temporary copy owned by this system may be cleaned up. The original service will not be restarted.",
  ],
  orphanInspectPending: ["Ожидается ответ сервера", "Awaiting host inspection"],
  orphanInspectRequested: [
    "Запрошена проверка фактического состояния. Исходное действие не повторяется.",
    "Actual state inspection requested. The original action is not repeated.",
  ],
  orphanFirstSeen: ["Впервые обнаружено", "First observed"],
  orphanLastSeen: ["Последнее сообщение", "Last reported"],
  alert_catalog_receipt_orphaned: [
    "Сервер сообщает об операции вне текущего каталога. Требуется проверка фактического состояния.",
    "A server reports an operation outside the current catalog. Its actual state must be inspected.",
  ],
  error_catalog_receipt_orphaned: [
    "Неподтвержденная операция сервера блокирует новые изменения. Сначала запросите проверку ее состояния.",
    "An unconfirmed server operation blocks new changes. Request an inspection of its actual state first.",
  ],
  error_orphan_not_found: [
    "Неподтвержденная операция не найдена. Обновите состояние.",
    "This unconfirmed operation was not found. Refresh the state.",
  ],
  error_orphan_already_terminal: [
    "Операция уже получила окончательный результат. Обновите состояние.",
    "This operation already has a terminal outcome. Refresh the state.",
  ],
  reconcile: ["Проверить фактический результат", "Reconcile actual outcome"],
  reconcileHelp: [
    "Сервер проверит сохраненный результат этой операции. Исходное действие повторно запускаться не будет.",
    "The server will inspect the saved outcome of this operation. The original action will not run again.",
  ],
  reconcileRequested: [
    "Запрошена проверка фактического результата.",
    "Actual outcome reconciliation requested.",
  ],
  reconnect: ["Подключить заново", "Reconnect"],
  revoke: ["Отозвать доступ", "Revoke access"],
  revoked: ["Доступ отозван", "Access revoked"],
  revokeHelp: [
    "Служба этого сервера потеряет доступ к панели. Данные сервиса и копии не удаляются. Для повторного подключения потребуется новая одноразовая команда.",
    "This server service will lose access to the panel. Service data and backups are not deleted. Reconnecting requires a new one-time command.",
  ],
  revokeDone: ["Доступ сервера отозван.", "Server access revoked."],
  pendingEnrollments: ["Ожидаемые подключения", "Pending enrollments"],
  cancelEnrollment: ["Отменить подключение", "Cancel enrollment"],
  enrollmentCancelled: [
    "Одноразовое подключение отменено.",
    "One-time enrollment cancelled.",
  ],
  cancelJob: ["Отменить ожидающую операцию", "Cancel queued operation"],
  cancelJobHelp: [
    "Будет отменена только операция, которая еще не отправлена серверу. Уже начатая работа этим действием не отменяется.",
    "Only an operation that has not been dispatched can be cancelled. Work that has already started is not cancelled by this action.",
  ],
  jobCancelled: ["Ожидающая операция отменена.", "Queued operation cancelled."],
  error_password_unchanged: [
    "Новый пароль должен отличаться от текущего.",
    "The new password must differ from the current password.",
  ],
  error_schedule_required: [
    "Сначала примените выбранное расписание на основной площадке.",
    "Apply the selected schedule on the primary site first.",
  ],
  alert_service_status_stale: [
    "Сведения о сервисе устарели. Дождитесь новой проверки сервера.",
    "Service observations are stale. Wait for a new host check.",
  ],
  error_password_change_required: [
    "Перед управлением измените первоначальный пароль.",
    "Change the initial password before managing protection.",
  ],
  error_node_busy: [
    "На сервере есть незавершенная операция. Сначала дождитесь или проверьте ее результат.",
    "The server has unfinished work. Wait for it or reconcile its outcome first.",
  ],
  error_job_not_cancellable: [
    "Операция уже отправлена серверу и не может быть отменена этим действием.",
    "The operation was dispatched and cannot be cancelled by this action.",
  ],
  error_cancelled_before_dispatch: [
    "Операция отменена до отправки на сервер.",
    "The operation was cancelled before dispatch.",
  ],
});
Object.assign(dictionary, {
  alert_catalog_receipt_orphaned: [
    "Сервер учитывает операцию, которой нет в каталоге. Перед новыми изменениями нужно установить ее результат.",
    "A host has an operation missing from the catalog. Establish its outcome before new changes."
  ]
});
Object.assign(dictionary, {
  "storage-configure": ["Подключение хранилища", "Connect storage"],
  "compose-register": ["Регистрация Compose", "Register Compose"],
  "compose-backup": ["Копирование сервиса", "Back up service"],
  "compose-verify": ["Проверка репозитория сервиса", "Verify service repository"],
  "compose-restore": ["Восстановление сервиса", "Restore service"],
  "compose-remove": ["Удаление отдельной копии", "Remove isolated restore"],
  "compose-schedule": ["Расписание сервиса", "Service schedule"],
  "compose-stop": ["Остановка источника", "Stop source"],
  "compose-activate": ["Активация новой копии", "Activate restored copy"],
  "compose-resume": ["Возобновление источника", "Resume source"]
});
const $ = (id) => document.getElementById(id);
const stored = (key, fallback) => {
  try {
    return localStorage.getItem(key) || fallback;
  } catch {
    return fallback;
  }
};
const save = (key, value) => {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage may be unavailable */
  }
};
const state = {
  lang: stored("rpo-language", "ru") === "en" ? "en" : "ru",
  session: null,
  overview: null,
  route: location.hash.slice(1) || "dashboard",
  step: 0,
  online: true,
  busy: false,
  lastRefresh: null,
  tracked: stored("rpo-operation", ""),
  target: "",
  snapshot: "",
  profile: "",
  interval: "",
  enrollment: null,
};
let toastTimer, pollTimer, dialogContext;
function t(key, values = {}) {
  let text = (dictionary[key] || dictionary.error_generic)[
    state.lang === "ru" ? 0 : 1
  ];
  for (const [k, v] of Object.entries(values))
    text = text.replaceAll(`{${k}}`, String(v));
  return text;
}
function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "value") node.value = v;
    else if (k === "checked") node.checked = Boolean(v);
    else if (k === "disabled") node.disabled = Boolean(v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined && child !== false)
      node.append(
        child instanceof Node ? child : document.createTextNode(String(child)),
      );
  }
  return node;
}
function button(label, callback, kind = "", props = {}) {
  return h(
    "button",
    { class: `btn ${kind}`, type: "button", onclick: callback, ...props },
    label,
  );
}
function pill(label, kind = "") {
  return h("span", { class: `status-pill ${kind}` }, label);
}
function notice(text, kind = "") {
  return h(
    "div",
    { class: `notice ${kind}`, role: kind === "bad" ? "alert" : "note" },
    h(
      "span",
      { class: "notice-symbol", "aria-hidden": "true" },
      kind === "bad" ? "!" : "ⓘ",
    ),
    h("p", {}, text),
  );
}
function brand() {
  return h(
    "a",
    { class: "brand", href: "#dashboard" },
    h("span", { class: "mark", "aria-hidden": "true" }),
    "RolyPolyOps",
  );
}
function date(value, compact = false) {
  if (!value) return t("noData");
  const d = new Date(value);
  if (!Number.isFinite(d.getTime())) return t("noData");
  return new Intl.DateTimeFormat(state.lang === "ru" ? "ru-RU" : "en-GB", {
    dateStyle: compact ? "short" : "medium",
    timeStyle: "short",
  }).format(d);
}
function age(value) {
  if (!value) return t("noData");
  const seconds = Math.max(0, (Date.now() - new Date(value).getTime()) / 1000);
  if (!Number.isFinite(seconds)) return t("noData");
  const n =
    seconds < 60
      ? 0
      : seconds < 3600
        ? -Math.floor(seconds / 60)
        : seconds < 86400
          ? -Math.floor(seconds / 3600)
          : -Math.floor(seconds / 86400);
  const unit = seconds < 3600 ? "minute" : seconds < 86400 ? "hour" : "day";
  return new Intl.RelativeTimeFormat(state.lang === "ru" ? "ru" : "en", {
    numeric: "auto",
  }).format(n, unit);
}
function bytes(value) {
  if (!Number.isFinite(Number(value))) return t("noData");
  return `${new Intl.NumberFormat(state.lang === "ru" ? "ru-RU" : "en-GB", { maximumFractionDigits: 1 }).format(Number(value) / 1024 ** 3)} GB`;
}
function shortId(value) {
  return typeof value === "string" ? value.slice(0, 12) : "—";
}
function nodeById(id) {
  return state.overview?.nodes.find((n) => n.id === id);
}
function primary() {
  return state.overview?.nodes.find((n) => n.role === "primary");
}
function target() {
  return (
    nodeById(state.target) ||
    state.overview?.nodes.find((n) => n.role === "recovery") ||
    primary()
  );
}
function fresh(node) {
  return (
    !node?.revoked &&
    Boolean(node?.connected) &&
    Number.isFinite(Date.parse(node.lastSeen)) &&
    Date.now() - Date.parse(node.lastSeen) < 45000 &&
    Number.isFinite(Date.parse(node.status?.observedAt)) &&
    Date.now() - Date.parse(node.status.observedAt) < 120000
  );
}
function nodeKind(node) {
  if (!fresh(node)) return "warn";
  if (!demoViewsSelected() && node.status?.compose) return node.status.compose.ready === true ? "" : "warn";
  if (node.status?.supported !== true) return "warn";
  return node.status?.serviceHealthy === true ? "" : "bad";
}
function nodeState(node) {
  if (node?.revoked) return t("revoked");
  if (!fresh(node)) return t("offline");
  if (!demoViewsSelected() && node.status?.compose) return node.status.compose.ready === true ? (state.lang === "ru" ? "Compose готов" : "Compose ready") : (state.lang === "ru" ? "Compose не готов" : "Compose not ready");
  if (node.status?.supported !== true) return t("unsupported");
  return t(node.status.serviceHealthy === true ? "healthy" : "unhealthy");
}
function jobKind(status) {
  return status === "succeeded"
    ? ""
    : status === "failed"
      ? "bad"
      : status === "outcome_unknown"
        ? "warn"
        : "neutral";
}
function snapshots() {
  const items = new Map();
  for (const s of target()?.status?.snapshots || []) {
    if (s && /^[a-f0-9]{64}$/.test(s.id)) items.set(s.id, s);
  }
  return [...items.values()].sort(
    (a, b) => Date.parse(b.time) - Date.parse(a.time),
  );
}
function jobs() {
  return [...(state.overview?.jobs || [])].sort(
    (a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt),
  );
}
function snapshotOf(job) {
  return job?.result?.snapshot || job?.result?.snapshotId || job?.snapshotId;
}
function latestBackupJob() {
  return jobs().find(
    (j) =>
      j.action === "backup" &&
      j.status === "succeeded" &&
      j.nodeId === primary()?.id,
  );
}
function setupSnapshot() {
  return snapshotOf(latestBackupJob());
}
function setupTarget() {
  return state.overview?.setup.profile === "single"
    ? primary()
    : target()?.role === "recovery"
      ? target()
      : state.overview?.nodes.find((n) => n.role === "recovery");
}
function setupScheduleReady() {
  const schedule = primary()?.status?.schedule?.backup;
  return (
    schedule?.enabled === true &&
    schedule.interval === state.overview?.setup.backupInterval
  );
}
function setupRestoreJob() {
  const id = setupSnapshot();
  return id
    ? jobs().find(
        (j) =>
          j.action === "restore-check" &&
          j.status === "succeeded" &&
          snapshotOf(j) === id &&
          j.nodeId === setupTarget()?.id,
      )
    : null;
}
function latestMetadata(key) {
  const a = (state.overview?.nodes || [])
    .filter(fresh)
    .map((n) => n.status?.[key])
    .filter(
      (value) => value && Number.isFinite(Date.parse(value.at || value.time)),
    );
  return a.sort(
    (x, y) => Date.parse(y.at || y.time) - Date.parse(x.at || x.time),
  )[0];
}
function errorText(error) {
  const aliases = {
    orphan_already_resolved: "orphan_already_terminal",
    authentication_failed: "invalid_credentials",
    login_rate_limited: "rate_limited",
    authentication_required: "unauthorized",
    csrf_forbidden: "csrf",
    package_unsupported: "unsupported_service",
    snapshot_unavailable: "invalid_snapshot",
    operation_in_progress: "operation_busy",
    nodes_not_ready: "setup_not_ready",
    nodes_required: "setup_not_ready",
    backup_required: "setup_not_ready",
    restore_check_required: "setup_not_ready",
    schedule_required: "schedule_required",
    primary_unavailable: "node_offline",
    preview_unavailable: "not_found",
    invalid_password: "invalid_credentials",
    csrf_failed: "csrf",
    csrf_invalid: "csrf",
    stale_revision: "revision_conflict",
    stale_plan: "plan_stale",
    snapshot_not_found: "invalid_snapshot",
    node_stale: "node_offline",
    not_ready: "setup_not_ready",
    busy: "operation_busy",
    password_weak: "password_too_short",
  };
  const key = `error_${aliases[error?.code] || error?.code || "generic"}`;
  return t(dictionary[key] ? key : "error_generic");
}
function toast(text) {
  $("toast").textContent = text;
  $("toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($("toast").hidden = true), 6500);
  $("announcements").textContent = text;
}
async function api(path, body) {
  const options = {
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
  };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    if (state.session?.csrf)
      options.headers["X-CSRF-Token"] = state.session.csrf;
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch("/ops" + path, options);
  } catch {
    const e = new Error("network");
    e.code = "network";
    throw e;
  }
  let result;
  try {
    result = await response.json();
  } catch {
    const e = new Error("invalid_response");
    e.code = "generic";
    throw e;
  }
  if (!response.ok) {
    const e = new Error("request_failed");
    e.code = result.error || "generic";
    e.http = response.status;
    if (response.status === 401 && path !== "/api/login") {
      managed.clear();
      state.session = { authenticated: false };
      state.overview = null;
      if ($("dialog").open) closeDialog();
      render();
    }
    throw e;
  }
  return result;
}
function setRoute(route) {
  if (
    !["dashboard", "services", "storages", "restore", "nodes", "history", "settings", "setup"].includes(
      route,
    )
  )
    route = "dashboard";
  state.route = route;
  location.hash = route;
  render();
  window.scrollTo({ top: 0, behavior: "instant" });
}
function langButton() {
  return h(
    "button",
    {
      class: "tiny-button",
      type: "button",
      "aria-label":
        state.lang === "ru" ? "Switch to English" : "Переключить на русский",
      onclick: () => {
        state.lang = state.lang === "ru" ? "en" : "ru";
        save("rpo-language", state.lang);
        $("toast").hidden = true;
        clearTimeout(toastTimer);
        render();
        if ($("dialog").open && dialogContext) renderDialog();
      },
    },
    state.lang === "ru" ? "EN" : "RU",
  );
}
function field(label, input, help) {
  const id = input.id || `field-${crypto.randomUUID()}`;
  input.id = id;
  if (help) input.setAttribute("aria-describedby", id + "-help");
  return h(
    "div",
    { class: "field" },
    h("label", { for: id }, label),
    input,
    help ? h("small", { id: id + "-help" }, help) : null,
  );
}
function select(options, value, onchange, props = {}) {
  const input = h("select", {
    ...props,
    onchange: (e) => onchange(e.target.value),
  });
  for (const [id, label] of options)
    input.append(h("option", { value: id }, label));
  input.value = value || "";
  return input;
}
function head(eyebrow, title, lead, actions = []) {
  return h(
    "div",
    { class: "page-head" },
    h(
      "div",
      {},
      h("div", { class: "eyebrow" }, eyebrow),
      h("h1", {}, title),
      h("p", { class: "page-subtitle" }, lead),
    ),
    actions.length ? h("div", { class: "actions" }, actions) : null,
  );
}
function render() {
  document.documentElement.lang = state.lang;
  document.title = `RolyPolyOps · ${t(state.route)}`;
  const app = $("app");
  app.replaceChildren();
  if (!state.session) {
    app.append(
      h(
        "main",
        { id: "main", class: "initial-loading", "aria-busy": "true" },
        h("span", { class: "spinner" }),
        "RolyPolyOps",
      ),
    );
    return;
  }
  if (!state.session.authenticated) {
    app.append(authView(false));
    return;
  }
  if (state.session.needsPasswordChange) {
    app.append(authView(true));
    return;
  }
  app.append(shell());
}
function authView(change) {
  const form = h(
    "form",
    {
      class: "auth-form",
      onsubmit: async (e) => {
        e.preventDefault();
        const error = form.querySelector(".form-error");
        error.textContent = "";
        const submit = form.querySelector("[type=submit]");
        submit.disabled = true;
        try {
          if (change) {
            const values = new FormData(form);
            if (values.get("newPassword") === values.get("currentPassword")) {
              error.textContent = t("error_password_unchanged");
              return;
            }
            if (values.get("newPassword") !== values.get("repeatPassword")) {
              error.textContent = t("passwordMismatch");
              return;
            }
            const result = await api("/api/password", {
              currentPassword: values.get("currentPassword"),
              newPassword: values.get("newPassword"),
            });
            state.session = await api("/api/session");
            toast(t("passwordChanged"));
          } else {
            const result = await api("/api/login", {
              password: new FormData(form).get("password"),
            });
            state.session = { authenticated: true, ...result };
            const session = await api("/api/session");
            state.session = session;
          }
          await refreshOverview(true);
        } catch (ex) {
          error.textContent = errorText(ex);
        } finally {
          submit.disabled = false;
        }
      },
    },
    h("h2", {}, t(change ? "changePasswordTitle" : "loginTitle")),
    h(
      "span",
      { class: "help" },
      t(change ? "changePasswordHelp" : "loginHelp"),
    ),
  );
  if (change) {
    form.append(
      field(
        t("currentPassword"),
        h("input", {
          type: "password",
          name: "currentPassword",
          autocomplete: "current-password",
          required: true,
        }),
      ),
      field(
        t("newPassword"),
        h("input", {
          type: "password",
          name: "newPassword",
          autocomplete: "new-password",
          minlength: 16,
          required: true,
        }),
        t("passwordHelp"),
      ),
      field(
        t("repeatPassword"),
        h("input", {
          type: "password",
          name: "repeatPassword",
          autocomplete: "new-password",
          minlength: 16,
          required: true,
        }),
      ),
    );
  } else
    form.append(
      field(
        t("password"),
        h("input", {
          type: "password",
          name: "password",
          autocomplete: "current-password",
          required: true,
          placeholder: t("passwordPlaceholder"),
        }),
      ),
    );
  form.append(
    h("p", { class: "form-error", role: "alert" }),
    h(
      "button",
      { class: "btn primary", type: "submit" },
      t(change ? "changePassword" : "signIn"),
    ),
    h("p", { class: "auth-footnote" }, t("authNote")),
  );
  return h(
    "div",
    { class: "auth-shell" },
    h(
      "section",
      { class: "auth-story" },
      brand(),
      h(
        "div",
        { class: "auth-story-content" },
        h("h1", {}, t("authTitle"), h("br"), h("em", {}, t("authAccent"))),
        h("p", {}, t("authLead")),
      ),
      h("p", { class: "auth-footer" }, t("authFooter")),
    ),
    h(
      "main",
      { class: "auth-main", id: "main" },
      h("div", { class: "auth-language" }, langButton()),
      form,
    ),
  );
}
function demoViewsSelected() {
  const overview=state.overview;
  if (overview?.setup?.demoSelected === true) return true;
  const nodes=overview?.nodes||[];
  if (overview?.setup?.demoSelected === false) return nodes.length>0 && !nodes.some(n=>n.status?.compose);
  // Older controllers do not expose selection. Preserve their legacy surface.
  return overview?.setup?.completed === true || nodes.some(n=>n.status?.supported === true) || !nodes.some(n=>n.status?.compose);
}
function shell() {
  const navItems = [
    ["dashboard", "▦"],
    ["services", "◈"],
    ["storages", "▱"],
    ["restore", "↶"],
    ["nodes", "▤"],
    ["history", "◷"],
    ["settings", "⚙"],
  ].filter(([id]) => demoViewsSelected() || !["restore", "settings"].includes(id));
  const sidebar = h(
    "aside",
    { class: "sidebar" },
    brand(),
    h("div", { class: "edition" }, t("edition")),
    h(
      "nav",
      { class: "nav", "aria-label": t("edition") },
      navItems.map(([id, icon]) =>
        h(
          "button",
          {
            type: "button",
            class: state.route === id ? "active" : "",
            "aria-current": state.route === id ? "page" : null,
            onclick: () => setRoute(id),
          },
          h("span", { class: "nav-icon", "aria-hidden": "true" }, icon),
          t(id),
        ),
      ),
    ),
    h(
      "div",
      { class: "sidebar-bottom" },
      h("strong", {}, t("sidebarTitle")),
      t("sidebarText"),
      h("div", { class: "scope" }, t("scope")),
      h(
        "div",
        { class: "scope" },
        `${t("version")} ${state.session.version || state.overview?.version || "—"}`,
      ),
    ),
  );
  const top = h(
    "header",
    { class: "topbar" },
    brand(),
    h("span", { class: "topbar-title" }, t("edition")),
    h(
      "div",
      { class: "topbar-controls" },
      h(
        "span",
        { class: "connection", role: "status" },
        h("span", { class: `dot ${state.online ? "" : "offline"}` }),
        t(state.online ? "connected" : "connectionLost"),
      ),
      langButton(),
      h(
        "button",
        {
          class: "tiny-button",
          type: "button",
          onclick: async () => {
            try {
              await api("/api/logout", {});
              managed.clear();
              state.session = { authenticated: false };
              state.overview = null;
              render();
            } catch (ex) {
              toast(errorText(ex));
            }
          },
        },
        t("logout"),
      ),
    ),
  );
  const main = h("main", { class: "main", id: "main" });
  if (!state.overview) {
    main.append(
      h(
        "div",
        { class: "initial-loading" },
        h("span", { class: "spinner" }),
        t("loading"),
      ),
    );
  } else {
    if (!state.online) main.append(notice(t("error_network"), "warn"));
    for (const alert of (state.overview.alerts || []).slice(0, 3)) {
      const k = `alert_${alert.code}`;
      main.append(
        notice(
          (dictionary[k] ? t(k) : managed.explain(alert.code)) +
            (alert.nodeId && nodeById(alert.nodeId)
              ? ` · ${nodeById(alert.nodeId).name}`
              : ""),
          alert.severity === "error" ? "bad" : "warn",
        ),
      );
    }
    const quarantined = orphanPanel();
    if (quarantined) main.append(quarantined);
    const banner = operationBanner();
    if (banner) main.append(banner);
    const views = {
      dashboard: dashboardView,
      services: managed.servicesView,
      storages: managed.storagesView,
      restore: restoreView,
      nodes: nodesView,
      history: historyView,
      settings: settingsView,
      setup: setupView,
    };
    main.append((views[state.route] || dashboardView)());
  }
  return h(
    "div",
    { class: "app-shell" },
    sidebar,
    h("div", { class: "content" }, top, main),
  );
}
function orphanPanel() {
  const reports = (state.overview?.orphanReports || []).filter(
    (report) => !["succeeded", "failed"].includes(report.status),
  );
  const overflowNodes = (state.overview?.nodes || []).filter(
    (node) => node.orphanOverflow === true,
  );
  if (!reports.length && !overflowNodes.length) return null;
  const overflowRows = overflowNodes.map((node) => {
    const online =
      !node.revoked &&
      node.connected &&
      Number.isFinite(Date.parse(node.lastSeen)) &&
      Date.now() - Date.parse(node.lastSeen) < 45000;
    const pending = node.overflowInspectionRequested === true;
    const request = () =>
      simpleConfirm(
        t("orphanInventoryInspect"),
        t("orphanInventoryConfirm"),
        async () => {
          const result = await api(
            `/api/nodes/${encodeURIComponent(node.id)}/orphans/reconcile`,
            {},
          );
          if (typeof result.inspectionRequested !== "boolean")
            throw Object.assign(new Error("invalid_response"), {
              code: "generic",
            });
          toast(
            t(
              result.inspectionRequested
                ? "orphanInspectRequested"
                : "orphanInventorySettled",
            ),
          );
        },
        t("orphanInventoryInspect"),
      );
    return h(
      "article",
      { class: "verification-row orphan-row orphan-overflow-row" },
      h(
        "div",
        {},
        h("h3", {}, node.name),
        h("p", { class: "help" }, t("orphanInventoryHelp")),
      ),
      h(
        "div",
        { class: "orphan-controls" },
        pill(
          t(pending ? "orphanInspectPending" : "orphanInventoryTitle"),
          "warn",
        ),
        !online ? h("span", { class: "help" }, t("offline")) : null,
        button(
          t(pending ? "orphanInspectPending" : "orphanInventoryInspect"),
          request,
          "small",
          { disabled: !online || pending },
        ),
      ),
    );
  });
  const rows = reports.map((report) => {
    const node = nodeById(report.nodeId);
    const id = report.id || report.jobId;
    const online =
      !node?.revoked &&
      node?.connected &&
      Number.isFinite(Date.parse(node.lastSeen)) &&
      Date.now() - Date.parse(node.lastSeen) < 45000;
    const pending =
      report.inspectionRequested === true || report.inspectRequested === true;
    const details = h(
      "div",
      {},
      h("h3", {}, node?.name || t("site")),
      h("p", { class: "mono" }, shortId(id)),
      h(
        "div",
        { class: "orphan-meta" },
        h(
          "span",
          {},
          t("orphanFirstSeen") + ": " + date(report.firstSeen, true),
        ),
        h("span", {}, t("orphanLastSeen") + ": " + date(report.lastSeen, true)),
      ),
    );
    const request = () =>
      simpleConfirm(
        t("orphanInspect"),
        t("orphanInspectHelp"),
        async () => {
          await api(
            `/api/nodes/${encodeURIComponent(report.nodeId)}/orphans/${encodeURIComponent(id)}/reconcile`,
            {},
          );
          toast(t("orphanInspectRequested"));
        },
        t("orphanInspect"),
      );
    const controls = h(
      "div",
      { class: "orphan-controls" },
      pill(
        t(
          pending
            ? "orphanInspectPending"
            : dictionary[report.status]
              ? report.status
              : "outcome_unknown",
        ),
        "warn",
      ),
      !online ? h("span", { class: "help" }, t("offline")) : null,
      button(
        t(pending ? "orphanInspectPending" : "orphanInspect"),
        request,
        "small",
        { disabled: !online || pending || !id },
      ),
    );
    return h(
      "article",
      { class: "verification-row orphan-row" },
      details,
      controls,
    );
  });
  return h(
    "section",
    { class: "card orphan-panel", "aria-label": t("orphanTitle") },
    h("div", { class: "card-head" }, h("h2", {}, t("orphanTitle"))),
    notice(t("orphanHelp"), "warn"),
    overflowRows,
    rows,
  );
}
function operationBanner() {
  const job =
    jobs().find((j) => j.id === state.tracked) ||
    jobs().find((j) =>
      ["queued", "dispatched", "running", "outcome_unknown"].includes(j.status),
    );
  if (!job) return null;
  const ongoing = ["queued", "dispatched", "running"].includes(job.status);
  return h(
    "section",
    { class: "job-banner", "aria-label": t("recentOperations") },
    h(
      "div",
      { class: "job-banner-top" },
      h(
        "div",
        {},
        h(
          "h3",
          {},
          `${t(job.action)} · ${nodeById(job.nodeId)?.name || t("site")}`,
        ),
        h(
          "p",
          {},
          t(
            job.status === "outcome_unknown"
              ? "unknownWarning"
              : ongoing
                ? "jobProgress"
                : job.status === "succeeded"
                  ? "jobFinished"
                  : "jobFailed",
          ),
        ),
      ),
      button(t("showDetails"), () => showJob(job), "small"),
    ),
    h(
      "div",
      { class: "actions section-gap" },
      pill(t(job.status), jobKind(job.status)),
      ongoing
        ? h("span", { class: "inline-state" }, stageText(job.stage))
        : null,
    ),
    ongoing
      ? h("div", { class: "progress-track", "aria-hidden": "true" }, h("span"))
      : null,
  );
}
function stageText(stage) {
  const s = String(stage || "").toLowerCase();
  if (/captur|stopp|dump/.test(s)) return t("stageCapture");
  if (/transfer|upload|backup/.test(s)) return t("stageTransfer");
  if (/cleanup|remov/.test(s)) return t("stageCleanup");
  if (/check|health|validat/.test(s)) return t("stageChecks");
  if (/verif|integrity/.test(s)) return t("stageVerify");
  if (/restor|load/.test(s)) return t("stageRestore");
  if (/queue|dispatch/.test(s)) return t("stageQueued");
  return t("stageRunning");
}
function metric(label, value, note) {
  return h(
    "article",
    { class: "metric" },
    h("div", { class: "metric-label" }, label),
    h("div", { class: "metric-number" }, value),
    h("div", { class: "metric-note" }, note),
  );
}
function siteBox(node, role) {
  return h(
    "div",
    { class: "site-box" },
    h("div", { class: "site-role" }, t(role)),
    h("div", { class: "site-name" }, node?.name || t("unassigned")),
    h("div", { class: "site-note" }, node ? nodeState(node) : t("noData")),
  );
}
function dashboardView() {
  if (!demoViewsSelected()) return managed.homeView();
  const view = h("div");
  const p = primary();
  view.append(
    head(t("controlEyebrow"), t("dashboardTitle"), t("dashboardLead"), [
      button(t("backupNow"), () => planOperation(p, "backup"), "primary", {
        disabled: !fresh(p) || p?.status?.supported !== true,
      }),
      button(t("viewRecovery"), () => setRoute("restore")),
      button(state.lang === "ru" ? "Подключить свой сервис" : "Connect your service", () => setRoute("services"), "primary"),
    ]),
  );
  if (!state.overview.setup?.completed)
    view.append(
      notice(t("setupIncomplete"), "warn"),
      button(
        t("finishSetup"),
        () => {
          state.step = 0;
          setRoute("setup");
        },
        "small",
      ),
    );
  const backup = latestMetadata("lastBackup"),
    restored = latestMetadata("lastRestore");
  const online = state.overview.nodes.filter(fresh);
  const free = online
    .map((n) => Number(n.status?.disk?.free))
    .filter(Number.isFinite);
  view.append(
    h(
      "div",
      { class: "metrics section-gap" },
      metric(
        t("onlineNodes"),
        `${online.length} / ${state.overview.nodes.length}`,
        t("ofNodes", { total: state.overview.nodes.length }),
      ),
      metric(
        t("latestBackup"),
        backup ? age(backup.at || backup.time) : t("noData"),
        t("backupAge"),
      ),
      metric(
        t("lastRestore"),
        restored ? age(restored.at || restored.time) : t("notChecked"),
        t("restoreAge"),
      ),
      metric(
        t("freeSpace"),
        free.length ? bytes(Math.min(...free)) : t("noData"),
        t("observedSpace"),
      ),
    ),
  );
  const recoveryNode = state.overview.nodes.find((n) => n.role === "recovery");
  const service = h(
    "section",
    { class: "card" },
    h(
      "div",
      { class: "card-head" },
      h(
        "div",
        {},
        h("h2", {}, t("protectedService")),
        h("p", { class: "card-description" }, t("serviceDescription")),
      ),
      p ? pill(nodeState(p), nodeKind(p)) : null,
    ),
    h(
      "div",
      { class: "service-graphic" },
      siteBox(p, "primary"),
      h("span", { class: "flow-arrow", "aria-hidden": "true" }, "→"),
      siteBox(recoveryNode || p, "recovery"),
    ),
    h(
      "div",
      { class: "actions section-gap" },
      button(t("checkRestore"), () => setRoute("restore"), "small"),
      button(
        t("verifyRepository"),
        () => planOperation(recoveryNode || p, "verify"),
        "small",
        { disabled: !fresh(recoveryNode || p) },
      ),
    ),
  );
  const checks = h(
    "section",
    { class: "card" },
    h("h2", {}, t("protectionState")),
    h(
      "ul",
      { class: "check-list section-gap" },
      [
        [Boolean(backup), t("backupPresent")],
        [Boolean(restored), t("restorePresent")],
        [
          state.overview.nodes.length > 0 && state.overview.nodes.every(fresh),
          t("nodesPresent"),
        ],
      ].map(([pass, label]) =>
        h(
          "li",
          {},
          h(
            "span",
            {
              class: `check-symbol ${pass ? "" : "pending"}`,
              "aria-hidden": "true",
            },
            pass ? "✓" : "·",
          ),
          h("span", {}, label),
        ),
      ),
    ),
  );
  view.append(
    h("div", { class: "grid-two" }, service, checks),
    h("div", { class: "section-gap" }, notice(t("automaticUnavailable"))),
    h(
      "section",
      { class: "card" },
      h(
        "div",
        { class: "card-head" },
        h("h2", {}, t("recentOperations")),
        button(t("allOperations"), () => setRoute("history"), "small"),
      ),
      jobTable(jobs().slice(0, 5)),
    ),
  );
  return view;
}
function jobTable(rows) {
  if (!rows.length)
    return h(
      "div",
      { class: "empty" },
      h("strong", {}, t("noOperations")),
      t("noOperationsHelp"),
    );
  const table = h(
    "table",
    { class: "data-table" },
    h(
      "thead",
      {},
      h(
        "tr",
        {},
        ["action", "site", "status", "started"].map((k) =>
          h("th", { scope: "col" }, t(k)),
        ),
        h(
          "th",
          { scope: "col" },
          h("span", { class: "sr-only" }, t("showDetails")),
        ),
      ),
    ),
    h(
      "tbody",
      {},
      rows.map((job) =>
        h(
          "tr",
          {},
          h(
            "td",
            { "data-label": t("action") },
            h("div", {}, t(dictionary[job.action] ? job.action : "action")),
            h("div", { class: "table-secondary mono" }, shortId(job.id)),
          ),
          h(
            "td",
            { "data-label": t("site") },
            nodeById(job.nodeId)?.name || "—",
          ),
          h(
            "td",
            { "data-label": t("status") },
            pill(
              t(dictionary[job.status] ? job.status : "outcome_unknown"),
              jobKind(job.status),
            ),
          ),
          h("td", { "data-label": t("started") }, date(job.createdAt, true)),
          h(
            "td",
            {},
            button(t("showDetails"), () => showJob(job), "small"),
          ),
        ),
      ),
    ),
  );
  return h("div", { class: "table-wrap" }, table);
}
function snapshotSelector() {
  const points = snapshots();
  if (!points.some((s) => s.id === state.snapshot))
    state.snapshot = points[0]?.id || "";
  return field(
    t("chooseSnapshot"),
    select(
      points.length
        ? points.map((s) => [s.id, `${date(s.time, true)} · ${shortId(s.id)}`])
        : [["", t("selectSnapshot")]],
      state.snapshot,
      (value) => {
        state.snapshot = value;
        render();
      },
      { disabled: !points.length },
    ),
    t("snapshotCount", { count: points.length }),
  );
}
function targetSelector(setup = false) {
  const nodes = setup
    ? state.overview.nodes.filter(
        (n) =>
          n.role ===
          (state.overview.setup.profile === "single" ? "primary" : "recovery"),
      )
    : state.overview.nodes;
  if (!nodes.some((n) => n.id === state.target))
    state.target =
      (nodes.find((n) => n.role === "recovery") || nodes[0])?.id || "";
  return field(
    t("chooseTarget"),
    select(
      nodes.map((n) => [n.id, `${n.name} · ${t(n.role)}`]),
      state.target,
      (value) => {
        state.target = value;
        render();
      },
      { disabled: !nodes.length },
    ),
  );
}
function restoreView() {
  const view = h("div");
  view.append(head(t("restoreEyebrow"), t("restoreTitle"), t("restoreLead")));
  const points = snapshots();
  const form = h(
    "section",
    { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, t("retainRestore"))),
    h("div", { class: "form-grid" }, targetSelector(), snapshotSelector()),
  );
  if (!points.length)
    form.append(
      h(
        "div",
        { class: "empty" },
        h("strong", {}, t("noSnapshots")),
        t("noSnapshotsHelp"),
      ),
    );
  const point = points.find((s) => s.id === state.snapshot);
  if (point)
    form.append(
      h(
        "dl",
        { class: "dialog-facts" },
        h("dt", {}, t("snapshotDate")),
        h("dd", {}, date(point.time)),
        h("dt", {}, t("dataAge")),
        h("dd", {}, age(point.time)),
        h("dt", {}, t("snapshot")),
        h("dd", { class: "mono" }, point.id),
      ),
    );
  form.append(
    notice(t("restoreExplanation")),
    h(
      "div",
      { class: "actions" },
      button(
        t("checkRestore"),
        () => planOperation(target(), "restore-check", state.snapshot),
        "primary",
        { disabled: !state.snapshot || !fresh(target()) },
      ),
      button(
        t("retainRestore"),
        () => planOperation(target(), "restore-preview", state.snapshot),
        "",
        {
          disabled:
            !state.snapshot ||
            !fresh(target()) ||
            Boolean(target()?.status?.preview),
        },
      ),
      button(
        t("verifyRepository"),
        () => planOperation(target(), "verify"),
        "",
        { disabled: !fresh(target()) },
      ),
    ),
  );
  view.append(form);
  for (const node of state.overview.nodes.filter((n) => n.status?.preview))
    view.append(previewCard(node));
  return view;
}
function checkName(check) {
  const key = `check_${String(check).replaceAll("-", "_")}`;
  return t(dictionary[key] ? key : "check_generic");
}
function previewCard(node) {
  const preview = node.status.preview;
  return h(
    "section",
    { class: "card" },
    h(
      "div",
      { class: "card-head" },
      h(
        "div",
        {},
        h("h2", {}, t("previewTitle")),
        h("p", { class: "card-description" }, node.name),
      ),
      pill(
        t(preview.checks?.length ? "checkPassed" : "notChecked"),
        preview.checks?.length ? "" : "neutral",
      ),
    ),
    h(
      "p",
      { class: "help" },
      t(preview.checks?.length ? "previewHelp" : "previewUnavailable"),
    ),
    h(
      "dl",
      { class: "dialog-facts" },
      h("dt", {}, t("previewSnapshot")),
      h(
        "dd",
        { class: "mono" },
        shortId(preview.snapshot || preview.snapshotId),
      ),
      h("dt", {}, t("snapshotDate")),
      h("dd", {}, date(preview.at || preview.createdAt)),
    ),
    h(
      "ul",
      { class: "check-list" },
      (preview.checks || []).map((c) =>
        h(
          "li",
          {},
          h("span", { class: "check-symbol", "aria-hidden": "true" }, "✓"),
          checkName(c),
        ),
      ),
    ),
    h(
      "div",
      { class: "form-actions" },
      button(
        t("removePreview"),
        () =>
          planOperation(node, "remove-preview", null, {
            previewId: node.status.preview.id,
          }),
        "danger small",
        { disabled: !fresh(node) },
      ),
    ),
  );
}
function nodesView() {
  const view = h("div");
  view.append(
    head(t("nodesEyebrow"), t("nodesTitle"), t("nodesLead"), [
      button(t("addNode"), enrollDialog, "primary"),
    ]),
  );
  view.append(managed.nodeSummary());
  if (!state.overview.nodes.length)
    view.append(
      h(
        "section",
        { class: "card empty" },
        h("strong", {}, t("noNodes")),
        t("noNodesHelp"),
      ),
    );
  else
    view.append(
      h("div", { class: "node-grid" }, state.overview.nodes.map(nodeCard)),
    );
  const pending = (state.overview.enrollments || []).filter(
    (x) => x.status === "pending",
  );
  if (pending.length)
    view.append(
      h(
        "section",
        { class: "card section-gap" },
        h("h2", {}, t("pendingEnrollments")),
        h(
          "div",
          { class: "section-gap" },
          pending.map((item) =>
            h(
              "div",
              { class: "verification-row" },
              h(
                "div",
                {},
                h("h3", {}, item.name),
                h(
                  "p",
                  {},
                  t("enrollmentExpires", { time: date(item.expiresAt) }),
                ),
              ),
              button(
                t("cancelEnrollment"),
                () =>
                  simpleConfirm(
                    t("cancelEnrollment"),
                    t("enrollHelp"),
                    async () => {
                      await api(
                        `/api/enrollments/${encodeURIComponent(item.id)}/cancel`,
                        {},
                      );
                      toast(t("enrollmentCancelled"));
                    },
                  ),
                "small danger",
              ),
            ),
          ),
        ),
      ),
    );
  return view;
}
function nodeCard(node) {
  const composeOnly = !demoViewsSelected() && Boolean(node.status?.compose);
  const disk = node.status?.disk;
  const used = disk?.total
    ? Math.min(100, Math.max(0, 100 - (100 * disk.free) / disk.total))
    : 0;
  const schedule = (kind, label) =>
    h(
      "div",
      {},
      h("div", { class: "detail-label" }, t(label)),
      h(
        "div",
        { class: "detail-value" },
        node.status?.schedule?.[kind]
          ? `${t(node.status.schedule[kind].enabled ? "enabled" : "disabled")}${dictionary[node.status.schedule[kind].interval] ? " · " + t(node.status.schedule[kind].interval) : ""}`
          : t("noData"),
      ),
      node.status?.schedule?.[kind]?.next
        ? h(
            "div",
            { class: "table-secondary" },
            t("nextRun", { time: date(node.status.schedule[kind].next, true) }),
          )
        : null,
    );
  return h(
    "article",
    { class: "card" },
    h(
      "div",
      { class: "card-head" },
      h(
        "div",
        {},
        h("div", { class: "eyebrow" }, t(node.role)),
        h("h2", { class: "node-title" }, node.name),
      ),
      pill(nodeState(node), nodeKind(node)),
    ),
    h(
      "div",
      { class: "node-details" },
      h(
        "div",
        {},
        h("div", { class: "detail-label" }, t("agentVersion")),
        h("div", { class: "detail-value" }, node.status?.version || "—"),
      ),
      h(
        "div",
        {},
        h("div", { class: "detail-label" }, t("lastSeen")),
        h("div", { class: "detail-value" }, date(node.lastSeen, true)),
      ),
      composeOnly ? h("div", {}, h("div", {class:"detail-label"}, state.lang === "ru" ? "Свои сервисы Compose" : "Own Compose services"), h("div", {class:"detail-value"}, node.status.compose.services?.length || 0)) : schedule("backup", "backupSchedule"),
      composeOnly ? h("div", {}, h("div", {class:"detail-label"}, t("storages")), h("div", {class:"detail-value"}, node.status.compose.storages?.filter(s=>s.connected).length || 0)) : schedule("restore", "restoreSchedule"),
    ),
    h(
      "div",
      { class: "detail-label" },
      disk
        ? t("diskFree", { free: bytes(disk.free), total: bytes(disk.total) })
        : t("noData"),
    ),
    h("progress", {
      class: "storage-bar",
      max: 100,
      value: used,
      "aria-label": t("freeSpace"),
      "aria-valuetext": disk
        ? t("diskFree", { free: bytes(disk.free), total: bytes(disk.total) })
        : t("noData"),
    }),
    node.status?.preview
      ? h("div", { class: "section-gap" }, pill(t("previewTitle")))
      : null,
    h(
      "div",
      { class: "form-actions" },
      button(
        t("reconnect"),
        async () => {
          try {
            const result = await api(
              `/api/nodes/${encodeURIComponent(node.id)}/enrollment`,
              {},
            );
            openDialog({ kind: "enroll", result });
          } catch (ex) {
            toast(errorText(ex));
          }
        },
        "small",
      ),
      !node.revoked
        ? button(
            t("revoke"),
            () =>
              simpleConfirm(t("revoke"), t("revokeHelp"), async () => {
                await api(
                  `/api/nodes/${encodeURIComponent(node.id)}/revoke`,
                  {},
                );
                toast(t("revokeDone"));
              }),
            "small danger",
          )
        : null,
    ),
  );
}
function historyView() {
  return h(
    "div",
    {},
    head(t("historyEyebrow"), t("historyTitle"), t("historyLead")),
    h("section", { class: "card" }, jobTable(jobs())),
  );
}
function policyFields() {
  state.profile =
    state.profile || state.overview.setup.profile || "pair_assisted";
  state.interval =
    state.interval || state.overview.setup.backupInterval || "hourly";
  return h(
    "div",
    {},
    h(
      "div",
      { class: "radio-cards" },
      ["single", "pair_assisted"].map((profile) =>
        h(
          "label",
          { class: "radio-card" },
          h("input", {
            type: "radio",
            name: "profile",
            value: profile,
            checked: state.profile === profile,
            onchange: () => {
              state.profile = profile;
              render();
            },
          }),
          h(
            "span",
            {},
            h("strong", {}, t(profile)),
            h("small", {}, t(profile === "single" ? "singleHelp" : "pairHelp")),
          ),
        ),
      ),
    ),
    field(
      t("backupInterval"),
      select(
        ["15min", "hourly", "daily"].map((v) => [v, t(v)]),
        state.interval,
        (value) => (state.interval = value),
      ),
    ),
  );
}
async function savePreferences() {
  await api("/api/settings", {
    profile: state.profile,
    backupInterval: state.interval,
    expectedRevision: state.overview.revision,
  });
  await refreshOverview(true);
  toast(t("settingsSaved"));
}
function scheduleSummary(node) {
  const value = node?.status?.schedule?.backup;
  if (!value) return t("noData");
  return `${t(value.enabled ? "enabled" : "disabled")}${dictionary[value.interval] ? " · " + t(value.interval) : ""}`;
}
function settingsView() {
  const p = primary();
  return h(
    "div",
    {},
    head(t("settingsEyebrow"), t("settingsTitle"), t("settingsLead")),
    h(
      "section",
      { class: "card" },
      h("h2", {}, t("profile")),
      h("div", { class: "section-gap" }, policyFields()),
      h(
        "div",
        { class: "form-actions" },
        button(
          t("savePreferences"),
          async (e) => {
            try {
              await savePreferences();
            } catch (ex) {
              toast(errorText(ex));
            }
          },
          "primary",
        ),
        button(
          t("applySchedule"),
          () =>
            planOperation(p, "set-schedule", null, {
              interval: state.interval,
            }),
          "",
          { disabled: !fresh(p) },
        ),
      ),
      h("p", { class: "help section-gap" }, t("scheduleHelp")),
      h(
        "div",
        { class: "section-gap" },
        h("div", { class: "detail-label" }, t("actualSchedule")),
        h("div", { class: "detail-value" }, scheduleSummary(p)),
        p?.status?.schedule?.backup?.next
          ? h(
              "div",
              { class: "table-secondary" },
              t("nextRun", { time: date(p.status.schedule.backup.next) }),
            )
          : null,
      ),
    ),
    h(
      "section",
      { class: "card" },
      h("div", { class: "card-head" }, h("h2", {}, t("account"))),
      h(
        "div",
        { class: "actions" },
        button(t("changePassword"), passwordDialog),
        button(t("rerunSetup"), () => {
          state.step = 0;
          setRoute("setup");
        }),
      ),
    ),
    h("div", { class: "section-gap" }, notice(t("automaticUnavailable"))),
  );
}
function setupView() {
  const view = h("div", { class: "wizard-layout" });
  view.append(
    head(t("setupEyebrow"), t("setupTitle"), t("setupLead")),
    h(
      "nav",
      { class: "stepper", "aria-label": t("setup") },
      ["stepNodes", "stepPolicy", "stepVerify", "stepReady"].map((key, i) =>
        h(
          "button",
          {
            type: "button",
            class: `step ${state.step === i ? "current" : ""}`,
            "aria-current": state.step === i ? "step" : null,
            onclick: () => {
              state.step = i;
              render();
            },
          },
          h("span", { class: "step-number" }, i + 1),
          t(key),
        ),
      ),
    ),
  );
  const card = h("section", { class: "card wizard-card" });
  if (state.step === 0) {
    card.append(
      h(
        "div",
        { class: "wizard-heading" },
        h("h2", {}, t("nodesTitle")),
        h("p", { class: "card-description" }, t("nodesStepHelp")),
      ),
    );
    if (!state.overview.nodes.length)
      card.append(
        h(
          "div",
          { class: "empty" },
          h("strong", {}, t("noNodes")),
          t("noNodesHelp"),
        ),
      );
    else
      card.append(
        h("div", { class: "node-grid" }, state.overview.nodes.map(nodeCard)),
      );
    card.append(
      h(
        "div",
        { class: "form-actions" },
        button(t("addNode"), enrollDialog, "primary"),
      ),
    );
  }
  if (state.step === 1) {
    card.append(
      h(
        "div",
        { class: "wizard-heading" },
        h("h2", {}, t("profile")),
        h("p", { class: "card-description" }, t("policyStepHelp")),
      ),
      policyFields(),
      h(
        "div",
        { class: "form-actions" },
        button(
          t("savePreferences"),
          async () => {
            try {
              await savePreferences();
            } catch (ex) {
              toast(errorText(ex));
            }
          },
          "primary",
        ),
        button(
          t("applySchedule"),
          () =>
            planOperation(primary(), "set-schedule", null, {
              interval: state.interval,
            }),
          "",
          { disabled: !fresh(primary()) },
        ),
      ),
    );
    if (state.profile === "single")
      card.append(
        h(
          "div",
          { class: "section-gap" },
          notice(t("sameHostWarning"), "warn"),
        ),
      );
  }
  if (state.step === 2) {
    const backup = latestBackupJob(),
      restored = setupRestoreJob();
    card.append(
      h(
        "div",
        { class: "wizard-heading" },
        h("h2", {}, t("verifyStepTitle")),
        h("p", { class: "card-description" }, t("verifyStepHelp")),
      ),
      h(
        "div",
        { class: "verification-row" },
        h(
          "div",
          {},
          h("h3", {}, t("firstBackup")),
          h(
            "p",
            {},
            backup
              ? `${t("checkPassed")} · ${shortId(snapshotOf(backup))}`
              : t("backupNeeded"),
          ),
        ),
        button(
          t("backupNow"),
          () => planOperation(primary(), "backup"),
          "primary",
          { disabled: !fresh(primary()) },
        ),
      ),
      targetSelector(true),
      h(
        "div",
        { class: "verification-row section-gap" },
        h(
          "div",
          {},
          h("h3", {}, t("firstRestore")),
          h("p", {}, restored ? t("checkPassed") : t("restoreNeeded")),
        ),
        button(
          t("checkRestore"),
          () => planOperation(setupTarget(), "restore-check", setupSnapshot()),
          "primary",
          { disabled: !setupSnapshot() || !fresh(setupTarget()) },
        ),
      ),
    );
  }
  if (state.step === 3) {
    const ready = Boolean(
      latestBackupJob() && setupRestoreJob() && setupScheduleReady(),
    );
    card.append(
      h(
        "div",
        { class: "finish-icon", "aria-hidden": "true" },
        ready ? "✓" : "↻",
      ),
      h("h2", {}, t(ready ? "readyTitle" : "setupNotReady")),
      h("p", { class: "card-description" }, t("readyHelp")),
      h(
        "ul",
        { class: "check-list section-gap" },
        [
          [Boolean(latestBackupJob()), t("backupPresent")],
          [Boolean(setupRestoreJob()), t("restorePresent")],
          [setupScheduleReady(), t("actualSchedule")],
          [
            state.overview.nodes.length > 0 &&
              state.overview.nodes.every(fresh),
            t("nodesPresent"),
          ],
        ].map(([ok, label]) =>
          h(
            "li",
            {},
            h(
              "span",
              {
                class: `check-symbol ${ok ? "" : "pending"}`,
                "aria-hidden": "true",
              },
              ok ? "✓" : "·",
            ),
            label,
          ),
        ),
      ),
      !ready
        ? h("div", { class: "section-gap" }, notice(t("setupNotReady"), "warn"))
        : null,
      h(
        "div",
        { class: "form-actions" },
        button(
          t("completeSetup"),
          async () => {
            try {
              await api("/api/setup/complete", {});
              await refreshOverview(true);
              toast(t("setupCompleted"));
              setRoute("dashboard");
            } catch (ex) {
              toast(errorText(ex));
            }
          },
          "primary",
          { disabled: !ready },
        ),
      ),
    );
  }
  const canNext =
    state.step === 0
      ? state.overview.nodes.some((n) => fresh(n) && n.status?.supported)
      : state.step === 2
        ? Boolean(latestBackupJob() && setupRestoreJob())
        : true;
  card.append(
    h(
      "div",
      { class: "step-footer" },
      state.step > 0
        ? button(t("back"), () => {
            state.step--;
            render();
          })
        : h("span"),
      state.step < 3
        ? button(
            t("next"),
            async () => {
              if (state.step === 1) {
                try {
                  await savePreferences();
                  state.step++;
                  render();
                  await planOperation(primary(), "set-schedule", null, {
                    interval: state.interval,
                  });
                } catch (ex) {
                  toast(errorText(ex));
                }
              } else {
                state.step++;
                render();
              }
            },
            "",
            { disabled: !canNext },
          )
        : button(t("dashboard"), () => setRoute("dashboard")),
    ),
  );
  view.append(card);
  return view;
}
function openDialog(context) {
  dialogContext = context;
  renderDialog();
  if (!$("dialog").open) $("dialog").showModal();
}
function closeDialog() {
  const d = $("dialog");
  d.close();
  d.replaceChildren();
  dialogContext = null;
  if (state.session?.authenticated && state.overview) render();
}
function dialogFrame(title, body, footer) {
  return [
    h(
      "div",
      { class: "dialog-body" },
      h(
        "div",
        { class: "dialog-head" },
        h("h2", { id: "dialog-title" }, title),
        h(
          "button",
          {
            class: "close-button",
            type: "button",
            "aria-label": t("close"),
            onclick: closeDialog,
          },
          "×",
        ),
      ),
      body,
    ),
    footer ? h("div", { class: "dialog-footer" }, footer) : null,
  ];
}
function renderDialog() {
  const d = $("dialog");
  d.replaceChildren();
  if (!dialogContext) return;
  const c = dialogContext;
  if (c.kind === "plan") {
    const p = c.plan;
    const node = nodeById(p.nodeId);
    const explanation =
      p.action === "backup"
        ? "confirmPause"
        : p.action === "remove-preview"
          ? "confirmRemove"
          : p.action === "set-schedule"
            ? "confirmSchedule"
            : p.action === "verify"
              ? "confirmVerify"
              : "confirmIsolated";
    const body = h(
      "div",
      {},
      notice(
        t(explanation),
        p.action === "backup" || p.action === "remove-preview" ? "warn" : "",
      ),
      h(
        "dl",
        { class: "dialog-facts" },
        h("dt", {}, t("action")),
        h("dd", {}, t(p.action)),
        h("dt", {}, t("site")),
        h("dd", {}, node?.name || "—"),
        p.snapshotId
          ? [
              h("dt", {}, t("snapshot")),
              h("dd", { class: "mono" }, p.snapshotId),
            ]
          : null,
        p.action === "set-schedule"
          ? [
              h("dt", {}, t("backupInterval")),
              h("dd", {}, t(p.parameters?.interval || state.interval)),
            ]
          : null,
      ),
      h("p", { class: "help" }, t("planExpires", { time: date(p.expiresAt) })),
      h("p", { class: "form-error", role: "alert", id: "dialog-error" }),
    );
    const confirm = button(
      t("planConfirm"),
      async () => {
        confirm.disabled = true;
        try {
          const result = await api("/api/jobs", {
            planId: p.id,
            idempotencyKey: c.idempotencyKey,
          });
          state.tracked = result.job.id;
          save("rpo-operation", state.tracked);
          closeDialog();
          toast(t("operationQueued"));
          await refreshOverview(true);
        } catch (ex) {
          const errorNode = $("dialog-error");
          if (errorNode) errorNode.textContent = errorText(ex);
          else toast(errorText(ex));
          confirm.disabled = false;
        }
      },
      p.action === "remove-preview" ? "danger" : "primary",
    );
    d.append(
      ...dialogFrame(t("planTitle"), body, [
        button(t("cancel"), closeDialog),
        confirm,
      ]).filter(Boolean),
    );
  }
  if (c.kind === "job") {
    const job = jobs().find((j) => j.id === c.id) || c.job;
    const checks = job.result?.checks || [];
    const body = h(
      "div",
      {},
      pill(
        t(dictionary[job.status] ? job.status : "outcome_unknown"),
        jobKind(job.status),
      ),
      h(
        "dl",
        { class: "dialog-facts" },
        h("dt", {}, t("operationId")),
        h("dd", { class: "mono" }, job.id),
        h("dt", {}, t("site")),
        h("dd", {}, nodeById(job.nodeId)?.name || "—"),
        h("dt", {}, t("started")),
        h("dd", {}, date(job.startedAt || job.createdAt)),
        job.endedAt
          ? [h("dt", {}, t("finished")), h("dd", {}, date(job.endedAt))]
          : null,
        snapshotOf(job)
          ? [
              h("dt", {}, t("snapshot")),
              h("dd", { class: "mono" }, snapshotOf(job)),
            ]
          : null,
      ),
      job.status === "outcome_unknown"
        ? notice(t("unknownWarning"), "warn")
        : null,
      job.status === "failed"
        ? notice(
            errorText({
              code: typeof job.error === "object" ? job.error?.code : job.error,
            }),
            "bad",
          )
        : null,
      checks.length
        ? h(
            "div",
            {},
            h("h3", {}, t("checks")),
            h(
              "ul",
              { class: "check-list section-gap" },
              checks.map((check) =>
                h(
                  "li",
                  {},
                  h(
                    "span",
                    { class: "check-symbol", "aria-hidden": "true" },
                    "✓",
                  ),
                  checkName(typeof check === "string" ? check : check.name),
                ),
              ),
            ),
          )
        : null,
      ["queued", "dispatched", "running"].includes(job.status)
        ? h(
            "div",
            {},
            h("p", { class: "help" }, stageText(job.stage)),
            h(
              "div",
              { class: "progress-track", "aria-hidden": "true" },
              h("span"),
            ),
          )
        : null,
    );
    const actions = [button(t("close"), closeDialog)];
    if (job.status === "outcome_unknown")
      actions.push(
        button(
          t("reconcile"),
          () =>
            simpleConfirm(t("reconcile"), t("reconcileHelp"), async () => {
              await api(
                `/api/jobs/${encodeURIComponent(job.id)}/reconcile`,
                {},
              );
              toast(t("reconcileRequested"));
            }),
          "primary",
        ),
      );
    if (job.status === "queued")
      actions.push(
        button(
          t("cancelJob"),
          () =>
            simpleConfirm(t("cancelJob"), t("cancelJobHelp"), async () => {
              await api(`/api/jobs/${encodeURIComponent(job.id)}/cancel`, {});
              toast(t("jobCancelled"));
            }),
          "danger",
        ),
      );
    d.append(
      ...dialogFrame(
        t(dictionary[job.action] ? job.action : "action"),
        body,
        actions,
      ).filter(Boolean),
    );
  }
  if (c.kind === "enroll") {
    if (c.result) {
      const result = c.result;
      const body = h(
        "div",
        {},
        h("p", { class: "help" }, t("enrollHelp")),
        h(
          "div",
          { class: "enrollment-code", tabindex: "0" },
          result.command || result.code,
        ),
        h(
          "p",
          { class: "help" },
          t("enrollmentExpires", { time: date(result.expiresAt) }),
        ),
        h(
          "p",
          { class: "help section-gap" },
          Date.parse(result.expiresAt) < Date.now()
            ? t("enrollmentExpired")
            : t("enrollmentWaiting"),
        ),
      );
      d.append(
        ...dialogFrame(t("enrollTitle"), body, [
          button(t("close"), closeDialog),
          button(
            t("copyCommand"),
            async () => {
              try {
                await navigator.clipboard.writeText(
                  result.command || result.code,
                );
                toast(t("copied"));
              } catch {
                toast(t("copyFailed"));
              }
            },
            "primary",
          ),
        ]).filter(Boolean),
      );
    } else {
      const input = h("input", {
        name: "name",
        required: true,
        maxlength: 80,
        placeholder: t("nodeNamePlaceholder"),
      });
      const role = select(
        [
          ["primary", t("primary")],
          ["recovery", t("recovery")],
        ],
        "recovery",
        () => {},
        { name: "role" },
      );
      const form = h(
        "form",
        {
          onsubmit: async (e) => {
            e.preventDefault();
            submit.disabled = true;
            try {
              const values = new FormData(form);
              const result = await api("/api/enrollments", {
                name: values.get("name").trim(),
                role: values.get("role"),
              });
              dialogContext = { kind: "enroll", result };
              renderDialog();
              await refreshOverview(false);
            } catch (ex) {
              error.textContent = errorText(ex);
              submit.disabled = false;
            }
          },
        },
        h("p", { class: "help" }, t("enrollHelp")),
        h(
          "div",
          { class: "form-grid section-gap" },
          field(t("nodeName"), input),
          field(t("nodeRole"), role),
        ),
      );
      const error = h("p", { class: "form-error", role: "alert" });
      const submit = h(
        "button",
        { type: "submit", class: "btn primary" },
        t("createEnrollment"),
      );
      form.append(error, h("div", { class: "form-actions" }, submit));
      d.append(
        ...dialogFrame(t("enrollTitle"), form, [
          button(t("cancel"), closeDialog),
        ]).filter(Boolean),
      );
    }
  }
  if (c.kind === "confirm") {
    const error = h("p", { class: "form-error", role: "alert" });
    const confirm = button(
      c.confirmLabel || t("planConfirm"),
      async () => {
        confirm.disabled = true;
        try {
          await c.run();
          closeDialog();
          await refreshOverview(true);
        } catch (ex) {
          error.textContent = errorText(ex);
          confirm.disabled = false;
        }
      },
      "primary",
    );
    d.append(
      ...dialogFrame(c.title, h("div", {}, notice(c.text, "warn"), error), [
        button(t("cancel"), closeDialog),
        confirm,
      ]).filter(Boolean),
    );
  }
  if (c.kind === "password") {
    const form = h(
      "form",
      {
        onsubmit: async (e) => {
          e.preventDefault();
          const values = new FormData(form);
          if (values.get("newPassword") === values.get("currentPassword")) {
            error.textContent = t("error_password_unchanged");
            return;
          }
          if (values.get("newPassword") !== values.get("repeatPassword")) {
            error.textContent = t("passwordMismatch");
            return;
          }
          submit.disabled = true;
          try {
            const result = await api("/api/password", {
              currentPassword: values.get("currentPassword"),
              newPassword: values.get("newPassword"),
            });
            state.session = { ...state.session, ...result };
            const session = await api("/api/session");
            state.session = session;
            closeDialog();
            toast(t("passwordChanged"));
          } catch (ex) {
            error.textContent = errorText(ex);
            submit.disabled = false;
          }
        },
      },
      h(
        "div",
        { class: "form-grid" },
        field(
          t("currentPassword"),
          h("input", {
            type: "password",
            name: "currentPassword",
            autocomplete: "current-password",
            required: true,
          }),
        ),
        field(
          t("newPassword"),
          h("input", {
            type: "password",
            name: "newPassword",
            autocomplete: "new-password",
            minlength: 16,
            required: true,
          }),
          t("passwordHelp"),
        ),
        field(
          t("repeatPassword"),
          h("input", {
            type: "password",
            name: "repeatPassword",
            autocomplete: "new-password",
            minlength: 16,
            required: true,
          }),
        ),
      ),
    );
    const error = h("p", { class: "form-error", role: "alert" }),
      submit = h(
        "button",
        { type: "submit", class: "btn primary" },
        t("changePassword"),
      );
    form.append(error, h("div", { class: "form-actions" }, submit));
    d.append(
      ...dialogFrame(t("changePassword"), form, [
        button(t("cancel"), closeDialog),
      ]).filter(Boolean),
    );
  }
}
function simpleConfirm(title, text, run, confirmLabel = null) {
  openDialog({ kind: "confirm", title, text, run, confirmLabel });
}
function enrollDialog() {
  openDialog({ kind: "enroll" });
}
function passwordDialog() {
  openDialog({ kind: "password" });
}
function showJob(job) {
  openDialog({ kind: "job", id: job.id, job });
}
async function planOperation(node, action, snapshotId, parameters) {
  if (!node) {
    toast(t("error_node_offline"));
    return;
  }
  if (state.busy) return;
  state.busy = true;
  try {
    const body = { nodeId: node.id, action };
    if (snapshotId) body.snapshotId = snapshotId;
    if (parameters) body.parameters = parameters;
    const plan = await api("/api/plans", body);
    openDialog({ kind: "plan", plan, idempotencyKey: crypto.randomUUID() });
  } catch (ex) {
    toast(errorText(ex));
  } finally {
    state.busy = false;
  }
}
async function refreshOverview(force = false) {
  if (!state.session?.authenticated || state.session.needsPasswordChange) {
    render();
    return;
  }
  try {
    const data = await api("/api/overview");
    if (!Array.isArray(data.nodes) || !Array.isArray(data.jobs) || !data.setup)
      throw Object.assign(new Error("invalid"), { code: "generic" });
    state.overview = data;
    state.online = true;
    state.lastRefresh = Date.now();
    const focused = document.activeElement;
    const editing =
      focused && ["INPUT", "SELECT", "TEXTAREA"].includes(focused.tagName);
    if (force || (!editing && !$("dialog").open)) render();
    if ($("dialog").open && dialogContext?.kind === "job") renderDialog();
  } catch (ex) {
    state.online = false;
    if (ex.http !== 401) {
      if (force) toast(errorText(ex));
      if (!state.overview) {
        $("app").replaceChildren(
          h(
            "main",
            { class: "initial-loading", id: "main" },
            h(
              "div",
              {},
              notice(t("error_network"), "bad"),
              button(t("refresh"), () => start(), "primary"),
            ),
          ),
        );
      } else if (!$("dialog").open) render();
    }
  }
}
async function start() {
  try {
    state.session = await api("/api/session");
    if (state.session.authenticated && !state.session.needsPasswordChange)
      await refreshOverview(true);
    else render();
  } catch (ex) {
    state.session = null;
    $("app").replaceChildren(
      h(
        "main",
        { class: "initial-loading", id: "main" },
        h(
          "div",
          {},
          notice(t("error_network"), "bad"),
          button(t("refresh"), start, "primary"),
        ),
      ),
    );
  }
  clearInterval(pollTimer);
  pollTimer = setInterval(() => refreshOverview(false), 5000);
}
$("dialog").addEventListener("cancel", () => {
  dialogContext = null;
});
$("dialog").addEventListener("close", () => {
  dialogContext = null;
});
window.addEventListener("hashchange", () => {
  state.route = location.hash.slice(1) || "dashboard";
  if (
    !["dashboard", "services", "storages", "restore", "nodes", "history", "settings", "setup"].includes(
      state.route,
    )
  )
    state.route = "dashboard";
  render();
});
window.addEventListener("online", () => refreshOverview(true));
const managed = createManagedUI({t,h,button,field,select,notice,pill,head,state,api,render,fresh,date,bytes,showJob,refreshOverview,setRoute});
start();
