<script setup>
import { ref, watch, onMounted } from 'vue'
import { useProgressStore } from '../stores/progress'

const props = defineProps({ lessonId: { type: String, required: true } })
const progress = useProgressStore()

const text = ref('')
const status = ref('')
let timer = null

onMounted(() => { text.value = progress.notes(props.lessonId) })
watch(() => props.lessonId, (id) => { text.value = progress.notes(id) })

function onInput() {
  status.value = 'печатаю…'
  clearTimeout(timer)
  timer = setTimeout(save, 900)
}

async function save() {
  try {
    await progress.saveNotes(props.lessonId, text.value)
    status.value = 'сохранено ✓'
    setTimeout(() => { if (status.value === 'сохранено ✓') status.value = '' }, 1500)
  } catch (e) {
    status.value = 'ошибка сохранения'
  }
}
</script>

<template>
  <div class="notes card">
    <div class="n-head">
      <h3>📝 Мои заметки</h3>
      <span class="status muted">{{ status }}</span>
    </div>
    <textarea
      v-model="text"
      class="ta"
      placeholder="Конспект, команды, полезные ссылки… Сохраняется автоматически."
      @input="onInput"
    ></textarea>
  </div>
</template>

<style scoped>
.notes { padding: 18px; margin: 28px 0; }
.n-head { display: flex; align-items: center; justify-content: space-between; }
.n-head h3 { margin: 0 0 12px; font-size: 1.05rem; }
.status { font-size: 12px; }
.ta {
  width: 100%; min-height: 150px; resize: vertical;
  background: var(--bg-soft); color: var(--text);
  border: 1px solid var(--border); border-radius: var(--r);
  padding: 13px 15px; font-family: var(--mono); font-size: 13.5px; line-height: 1.6;
  outline: none; transition: border-color .15s, box-shadow .15s;
}
.ta:focus { border-color: var(--accent); box-shadow: var(--glow); }

@media (max-width: 560px) {
  .notes { padding: 14px; margin: 22px 0; }
  /* 16px — иначе iOS зумит страницу при фокусе на поле. */
  .ta { font-size: 16px; padding: 12px 13px; }
}
</style>
