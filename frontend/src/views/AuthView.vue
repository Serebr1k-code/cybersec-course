<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { useProgressStore } from '../stores/progress'

const auth = useAuthStore()
const progress = useProgressStore()
const router = useRouter()

const mode = ref('login') // 'login' | 'register'
const username = ref('')
const password = ref('')
const busy = ref(false)
const error = ref('')

const title = computed(() => (mode.value === 'login' ? 'Вход' : 'Регистрация'))
const submitLabel = computed(() => (mode.value === 'login' ? 'Войти' : 'Создать аккаунт'))

function switchMode(m) {
  mode.value = m
  error.value = ''
}

async function submit() {
  if (busy.value) return
  error.value = ''
  if (!username.value || !password.value) {
    error.value = 'Введите логин и пароль'
    return
  }
  busy.value = true
  try {
    if (mode.value === 'login') await auth.login(username.value, password.value)
    else await auth.register(username.value, password.value)
    // Прогресс мог слиться с анонимным — подтягиваем актуальное состояние.
    await progress.load()
    router.push('/')
  } catch (e) {
    error.value = e.message || 'Не удалось выполнить запрос'
  } finally {
    busy.value = false
  }
}

async function logout() {
  await auth.logout()
  await progress.load()
  router.push('/')
}
</script>

<template>
  <div class="auth-view">
    <section v-if="auth.isLoggedIn" class="card box">
      <h1>Аккаунт</h1>
      <p class="who">Вы вошли как <b>{{ auth.username }}</b>.</p>
      <p class="muted">
        Прогресс, заметки и результаты квизов хранятся на сервере и доступны с любого устройства.
      </p>
      <div class="actions">
        <button class="btn" @click="logout">Выйти</button>
        <RouterLink to="/" class="btn btn-ghost">К дереву</RouterLink>
      </div>
    </section>

    <section v-else class="card box">
      <h1>{{ title }}</h1>
      <p class="muted">
        Войдите, чтобы прогресс сохранялся на сервере. Без входа всё работает как раньше —
        прогресс хранится в этом браузере.
      </p>

      <div class="tabs">
        <button class="tab" :class="{ on: mode === 'login' }" @click="switchMode('login')">Вход</button>
        <button class="tab" :class="{ on: mode === 'register' }" @click="switchMode('register')">Регистрация</button>
      </div>

      <form @submit.prevent="submit">
        <label class="field">
          <span>Логин</span>
          <input
            v-model.trim="username"
            type="text"
            autocomplete="username"
            placeholder="например, analyst"
            :disabled="busy"
          />
        </label>
        <label class="field">
          <span>Пароль</span>
          <input
            v-model="password"
            type="password"
            :autocomplete="mode === 'login' ? 'current-password' : 'new-password'"
            placeholder="минимум 6 символов"
            :disabled="busy"
          />
        </label>

        <p v-if="error" class="err">{{ error }}</p>

        <button class="btn btn-primary submit" type="submit" :disabled="busy">
          {{ busy ? 'Подождите…' : submitLabel }}
        </button>
      </form>

      <p class="hint muted">
        Логин: 3–32 символа (буквы, цифры, <code>.</code> <code>_</code> <code>-</code>), пароль от 6 символов.
      </p>
    </section>
  </div>
</template>

<style scoped>
.auth-view { max-width: 460px; margin: 40px auto; padding: 0 20px 80px; }
.box { padding: 26px 26px 24px; }
h1 { font-size: 1.5rem; margin: 0 0 10px; }
.muted { color: var(--muted); font-size: 13.5px; line-height: 1.6; }
.who { font-size: 15px; margin: 0 0 8px; }

.tabs { display: flex; gap: 6px; margin: 20px 0 16px; }
.tab {
  flex: 1;
  padding: 8px 10px;
  border-radius: var(--r);
  border: 1px solid var(--border);
  background: var(--panel-2);
  color: var(--text-soft);
  font: inherit;
  font-size: 13.5px;
  font-weight: 600;
  cursor: pointer;
}
.tab.on { background: var(--panel-3); color: var(--text); border-color: var(--border-strong); }

.field { display: flex; flex-direction: column; gap: 6px; margin-bottom: 14px; }
.field > span { font-size: 12.5px; font-weight: 600; color: var(--text-soft); }
.field input {
  padding: 10px 12px;
  border-radius: var(--r);
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--text);
  font: inherit;
  font-size: 14px;
  outline: none;
}
.field input:focus { border-color: var(--accent); box-shadow: var(--glow); }

.err {
  margin: 0 0 12px;
  padding: 9px 12px;
  border-radius: var(--r);
  background: rgba(239, 68, 68, .12);
  border: 1px solid rgba(239, 68, 68, .4);
  color: #fecaca;
  font-size: 13px;
}

.submit { width: 100%; justify-content: center; margin-top: 4px; }
.actions { display: flex; gap: 10px; margin-top: 18px; }
.hint { margin-top: 16px; font-size: 12px; }
code { font-family: var(--mono); background: var(--panel-3); border: 1px solid var(--border-soft); border-radius: 4px; padding: 0 4px; }
</style>
