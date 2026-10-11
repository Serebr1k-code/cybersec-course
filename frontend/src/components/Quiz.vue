<script setup>
import { ref, computed, watch } from 'vue'
import { useProgressStore } from '../stores/progress'

const props = defineProps({
  lessonId: { type: String, required: true },
  questions: { type: Array, required: true }
})

// Прогресс секции «Квиз» управляется ОТВЕТАМИ, а не таймером чтения:
// parent (LessonView) слушает @progress и заполняет кольцо секции долей
// отвеченных вопросов. `answered` эмитится один раз, когда отвечено всё.
const emit = defineEmits(['progress', 'answered'])

const progress = useProgressStore()
// answers[i] = выбранный индекс или -1. Вопрос «решён» (заблокирован),
// как только по нему дан первый ответ — менять его нельзя.
const answers = ref(props.questions.map(() => -1))
const saving = ref(false)

const score = computed(() => props.questions.reduce((s, q, i) => s + (answers.value[i] === q.answer ? 1 : 0), 0))
const answeredAll = computed(() => answers.value.every((a) => a >= 0))
const answeredCount = computed(() => answers.value.filter((a) => a >= 0).length)
const answeredRatio = computed(() => (props.questions.length ? answeredCount.value / props.questions.length : 0))
const prior = computed(() => progress.quiz(props.lessonId))

// Вопрос заблокирован после первого клика (per-question, а не общий флаг).
const isResolved = (qi) => answers.value[qi] >= 0
const isCorrect = (qi) => answers.value[qi] === props.questions[qi]?.answer

// Сообщаем родителю долю отвеченных вопросов (0..1) и их число.
function emitProgress() {
  emit('progress', answeredRatio.value, answeredCount.value)
  if (props.questions.length && answeredRatio.value >= 1) emit('answered')
}

async function choose(qi, oi) {
  if (isResolved(qi)) return // ответ уже дан — вопрос заблокирован
  answers.value[qi] = oi
  emitProgress()
  // Когда отвечено всё — фиксируем счёт в бэкенде (он хранит лучший).
  if (answeredAll.value) {
    saving.value = true
    try { await progress.submitQuiz(props.lessonId, score.value, props.questions.length) }
    catch (e) { /* фиксация счёта — best effort, UI уже показал результат */ }
    finally { saving.value = false }
  }
}

function reset() {
  answers.value = props.questions.map(() => -1)
  emitProgress()
}

// LessonView переиспользует этот компонент при SPA-навигации между уроками
// (у секции «Квиз» во всех уроках один и тот же id), поэтому при смене
// набора вопросов состояние нужно сбросить, иначе новый квиз показывался бы
// с ответами предыдущего урока.
watch(() => props.questions, () => reset())
</script>

<template>
  <div class="quiz card">
    <div class="q-head">
      <h3>🧠 Проверка знаний</h3>
      <div class="q-sub">
        <span class="chip">{{ questions.length }} вопрос(ов)</span>
        <span v-if="prior.total" class="chip" :class="{ good: prior.best === prior.total }">
          лучший: {{ prior.best }}/{{ prior.total }}
        </span>
      </div>
    </div>

    <div v-for="(q, qi) in questions" :key="qi" class="question">
      <p class="q-text"><span class="q-num">{{ qi + 1 }}</span> {{ q.question || q.text }}</p>
      <div class="options">
        <button
          v-for="(opt, oi) in q.options"
          :key="oi"
          class="option"
          :class="{
            correct: isResolved(qi) && oi === q.answer,
            wrong: isResolved(qi) && answers[qi] === oi && oi !== q.answer
          }"
          :disabled="isResolved(qi)"
          :aria-pressed="answers[qi] === oi"
          @click="choose(qi, oi)"
        >
          <span class="marker">{{ String.fromCharCode(65 + oi) }}</span>
          <span class="opt-text">{{ opt }}</span>
          <span v-if="isResolved(qi) && oi === q.answer" class="ic ok">✓</span>
          <span v-else-if="isResolved(qi) && answers[qi] === oi" class="ic bad">✕</span>
        </button>
      </div>
      <p
        v-if="isResolved(qi) && q.explanation"
        class="explain"
        :class="{ ok: isCorrect(qi), bad: !isCorrect(qi) }"
      >
        {{ q.explanation }}
      </p>
    </div>

    <div class="q-foot">
      <template v-if="answeredAll">
        <div class="result" :class="{ perfect: score === questions.length }">
          <b>{{ score }} / {{ questions.length }}</b>
          <span v-if="score === questions.length">Идеально! +{{ questions.length * 10 }} XP 🎉</span>
          <span v-else-if="score >= questions.length / 2">Неплохо, разберите ошибки и попробуйте снова.</span>
          <span v-else>Стоит перечитать урок и попробовать ещё раз.</span>
        </div>
      </template>
      <span v-else class="hint muted">Отвечайте на вопросы по одному — ответ проверяется сразу.</span>
      <button v-if="answeredCount > 0" class="btn" @click="reset">Пройти заново</button>
    </div>
  </div>
</template>

<style scoped>
.quiz { padding: 22px; margin: 28px 0; }
.q-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.q-head h3 { margin: 0; font-size: 1.15rem; }
.q-sub { display: flex; gap: 8px; }
.chip.good { background: rgba(34,197,94,.15); border-color: rgba(34,197,94,.4); color: #86efac; }

.question { margin: 20px 0; }
.q-text { display: flex; gap: 10px; font-weight: 600; color: var(--text); margin: 0 0 10px; }
.q-num {
  flex: none; width: 24px; height: 24px; border-radius: 7px;
  display: grid; place-items: center; font-size: 13px;
  background: var(--panel-3); color: var(--accent); font-weight: 800;
}
.options { display: flex; flex-direction: column; gap: 8px; }
.option {
  display: flex; align-items: center; gap: 11px;
  width: 100%; text-align: left; cursor: pointer;
  padding: 11px 13px; border-radius: var(--r);
  background: var(--panel-2); border: 1px solid var(--border);
  color: var(--text-soft); font: inherit; font-size: 14px;
  transition: background .13s, border-color .13s, transform .08s;
}
.option:hover:not(:disabled) { background: var(--panel-3); border-color: var(--border-strong); }
.option:active:not(:disabled) { transform: translateY(1px); }
.option:disabled { cursor: default; }
.marker {
  flex: none; width: 24px; height: 24px; border-radius: 50%;
  display: grid; place-items: center; font-size: 12px; font-weight: 800;
  background: var(--panel-3); color: var(--text-soft);
}
.opt-text { flex: 1; }
.option.correct { border-color: var(--green); background: rgba(34,197,94,.12); }
.option.correct .marker { background: var(--green); color: #05210f; }
.option.wrong { border-color: var(--red); background: rgba(239,68,68,.1); }
.option.wrong .marker { background: var(--red); color: #2b0606; }
.ic { font-weight: 900; }
.ic.ok { color: var(--green); }
.ic.bad { color: var(--red); }

.explain {
  margin: 10px 0 0; padding: 9px 12px; border-radius: var(--r);
  font-size: 13.5px; line-height: 1.5;
  border-left: 3px solid var(--border-strong);
  background: var(--panel-2); color: var(--text-soft);
}
.explain.ok { border-left-color: var(--green); }
.explain.bad { border-left-color: var(--red); }

.q-foot { display: flex; align-items: center; gap: 14px; margin-top: 22px; flex-wrap: wrap; }
.hint { font-size: 13px; }
.result { display: flex; align-items: baseline; gap: 12px; }
.result b { font-size: 1.3rem; color: var(--text); }
.result span { font-size: 13.5px; color: var(--muted); }
.result.perfect b { color: var(--green); }

/* Телефоны: варианты — во всю ширину, крупнее и удобнее для пальца. */
@media (max-width: 560px) {
  .quiz { padding: 16px 14px; margin: 22px 0; }
  .q-head { gap: 8px; }
  .option { padding: 12px 13px; font-size: 15px; gap: 10px; }
  .marker { width: 26px; height: 26px; }
  .q-foot { gap: 10px; }
}
</style>
