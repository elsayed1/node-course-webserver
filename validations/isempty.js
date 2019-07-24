
const isEmpty = anything =>{
    return (
    typeof anything === 'undefined' ||
    anything === null ||
    typeof anything === 'string' && anything.trim().length === 0 
    )
}
module.exports = isEmpty;